//! Router HTML console: halaman login, sesi berbasis cookie, dan dashboard.
//!
//! Console tidak memakai `Authorization: Bearer` di browser karena token tidak
//! boleh mendarat di URL, riwayat, atau body HTML. Yang dipakai cookie
//! `httpOnly`. Middleware `session_gate` membaca cookie itu, memverifikasinya
//! dengan aturan yang sama seperti API (aud `core`), lalu menyerahkan token ke
//! penegakan registry lewat header Authorization sintetis supaya hanya ada satu
//! jalur verifikasi yang dipakai bersama API.
//!
//! Verifikasi terjadi dua kali per request (gate + registry) dan itu disengaja:
//! harga satu verifikasi RSA jauh lebih murah daripada memfork aturan otorisasi.

pub mod apps;
pub mod audit;
pub mod helpers;
pub mod rbac;
pub mod users;
pub mod views;

use askama::Template;
use axum::Extension;
use axum::Form;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::jwt::{Claims, sign_access, verify_access};
use crate::auth::password::verify_password;
use crate::console::helpers::hash_refresh_token;
use crate::console::views::{DashboardPage, ErrorPage, LoginPage};
use crate::db::apps as db_apps;
use crate::db::users as db_users;
use crate::db::users::UserStatus;
use crate::db::{rbac as db_rbac, sessions};
use crate::error::AppError;
use crate::middleware::csrf;
use crate::middleware::ratelimit::{PeerAddr, client_ip};
use crate::state::AppState;

/// Cookie pembawa access token. `httpOnly` supaya tidak bisa dibaca skrip.
pub const ACCESS_COOKIE: &str = "sanca_access";

/// Cookie pembawa refresh token; hanya dipakai untuk mencabut sesi saat logout.
pub const REFRESH_COOKIE: &str = "sanca_refresh";

/// App pemilik console. Semua token console wajib ber-aud ini.
const CONSOLE_APP: &str = "core";

/// Batas panjang user-agent yang disimpan di baris sesi.
const MAX_USER_AGENT: usize = 512;

/// Panjang refresh token mentah, dalam byte, sebelum di-encode base64url.
const REFRESH_BYTES: usize = 32;

/// Hapus cookie sesi. Nilainya statis supaya tidak ada yang perlu di-escape.
const CLEAR_ACCESS: &str = "sanca_access=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax";
const CLEAR_REFRESH: &str = "sanca_refresh=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax";

/// Identitas hasil verifikasi cookie, ditempel `session_gate` ke extensions.
#[derive(Debug, Clone)]
pub struct ConsoleSession {
    pub claims: Claims,
}

/// Router console. Route-nya terdaftar di `rbac::registry`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/console/login", get(login_page).post(login_submit))
        .route("/console/logout", post(logout))
        .route("/console", get(dashboard))
        .merge(users::router())
        .merge(apps::router())
        .merge(rbac::router())
        .merge(audit::router())
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
    /// Kosong kalau form tidak membawanya; itu urusan pemeriksaan CSRF, bukan
    /// urusan parsing. Tanpa `default`, request tanpa token dijawab 422 oleh
    /// ekstraktor sebelum handler sempat menolaknya dengan 403.
    #[serde(default)]
    pub _csrf: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutForm {
    #[serde(default)]
    pub _csrf: String,
}

/// Middleware sesi console: jalan sebelum penegakan registry, hanya untuk path
/// `/console` yang memang butuh login.
///
/// Tanpa cookie atau dengan token yang tidak sah, pengguna dikirim ke halaman
/// login (303), bukan dijawab JSON 401 — di browser, 401 adalah jalan buntu.
pub async fn session_gate(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    if !path.starts_with("/console") {
        return next.run(request).await;
    }

    // Halaman login dan logout sengaja publik: keduanya justru dipakai saat
    // sesi belum ada atau sudah mau dibuang.
    if path == "/console/login" || path == "/console/logout" {
        return next.run(request).await;
    }

    let cookie_header = request
        .headers()
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok());

    let token = helpers::cookie_value(cookie_header, ACCESS_COOKIE).unwrap_or_default();
    let claims = if token.is_empty() {
        None
    } else {
        verify_access(&state.config, &state.signing, token, CONSOLE_APP).ok()
    };

    let Some(claims) = claims else {
        return redirect_to_login(true, state.config.is_prod());
    };

    // Salinan token ke header Authorization: penegakan registry yang sudah ada
    // yang memutuskan boleh atau tidak, jadi tidak ada aturan kedua yang bisa
    // menyimpang dari API.
    if let Ok(value) = format!("Bearer {token}").parse() {
        request.headers_mut().insert(header::AUTHORIZATION, value);
    }
    request.extensions_mut().insert(ConsoleSession { claims });

    next.run(request).await
}

/// GET /console/login — form biasa (tanpa HTMX) dengan token CSRF.
async fn login_page(State(state): State<AppState>, jar: CookieJar) -> Response {
    let (token, _) = csrf::token(&jar);
    let page = LoginPage {
        csrf: token.clone(),
        email: String::new(),
        error: None,
    };

    match render(page) {
        Ok(body) => (jar.add(csrf::cookie(token, state.config.is_prod())), body).into_response(),
        Err(err) => err.into_response(),
    }
}

/// POST /console/login — tukar email + password dengan cookie sesi.
///
/// Alurnya sama dengan `POST /api/auth/login` (app core, user aktif, verifikasi
/// Argon2id, lalu sesi + access token). Yang berbeda hanya cara membawa token:
/// ke browser lewat cookie, bukan JSON.
async fn login_submit(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    peer: PeerAddr,
    Form(form): Form<LoginForm>,
) -> Response {
    if !csrf::matches(&jar, &form._csrf) {
        return csrf_rejected(jar);
    }

    let ip = client_ip(&headers, peer.0);

    if state.login_limiter.is_blocked(&form.email, &ip) {
        return login_error(
            &state,
            jar,
            &form.email,
            StatusCode::TOO_MANY_REQUESTS,
            "Terlalu banyak percobaan. Tunggu beberapa menit lalu coba lagi.",
        );
    }

    let Some(issued) = issue_console_session(&state, &form, &headers, &ip).await else {
        state.login_limiter.record_failure(&form.email, &ip);
        return login_error(
            &state,
            jar,
            &form.email,
            StatusCode::UNAUTHORIZED,
            "Email atau password tidak cocok.",
        );
    };

    state.login_limiter.clear(&form.email, &ip);

    let secure = state.config.is_prod();
    let access = Cookie::build((ACCESS_COOKIE, issued.access_token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .max_age(time::Duration::seconds(issued.access_ttl))
        .build();
    let refresh = Cookie::build((REFRESH_COOKIE, issued.refresh_token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .max_age(time::Duration::seconds(issued.refresh_ttl))
        .build();

    // Cookie CSRF ikut dipertahankan supaya form berikutnya (logout) tetap sah.
    (jar.add(access).add(refresh), Redirect::to("/console")).into_response()
}

/// POST /console/logout — cabut sesi lalu buang kedua cookie.
async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LogoutForm>,
) -> Response {
    if !csrf::matches(&jar, &form._csrf) {
        return csrf_rejected(jar);
    }

    if let Some(token) = jar.get(REFRESH_COOKIE) {
        let hash = hash_refresh_token(token.value());
        match sessions::by_refresh_hash(&state.pool, &hash).await {
            Ok(Some(session)) => {
                if let Err(err) = sessions::revoke(&state.pool, session.id).await {
                    // Sesi gagal dicabut tetap membuat cookie dibuang; pengguna
                    // harus login ulang, dan sesi itu kedaluwarsa sendiri.
                    tracing::warn!(error = %err, "gagal mencabut sesi console");
                }
            }
            Ok(None) => {}
            Err(err) => tracing::warn!(error = %err, "gagal mencari sesi console"),
        }
    }

    let mut response = Redirect::to("/console/login").into_response();
    clear_session_cookies(&mut response, state.config.is_prod());
    response
}

/// GET /console — dashboard sederhana: angka katalog + tombol keluar.
async fn dashboard(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
) -> Response {
    let user_id = match Uuid::parse_str(&session.claims.sub) {
        Ok(id) => id,
        Err(_) => return redirect_to_login(true, state.config.is_prod()),
    };

    let Ok(Some(user)) = db_users::detail(&state.pool, user_id).await else {
        return redirect_to_login(true, state.config.is_prod());
    };

    let counts = sqlx::query!(
        r#"
        SELECT (SELECT count(*) FROM users WHERE status = 'active') AS "users_active!",
               (SELECT count(*) FROM apps) AS "apps_count!",
               (SELECT count(*) FROM roles) AS "roles_count!",
               (SELECT count(*) FROM permissions) AS "permissions_count!",
               (SELECT count(*) FROM sessions
                WHERE revoked_at IS NULL AND expires_at > now()) AS "sessions_active!",
               (SELECT count(*) FROM audit_events
                WHERE occurred_at > now() - interval '24 hours') AS "audit_24h!"
        "#
    )
    .fetch_one(&state.pool)
    .await;

    let counts = match counts {
        Ok(counts) => counts,
        Err(err) => {
            tracing::error!(error = %err, "gagal menghitung ringkasan dashboard");
            return AppError::Internal.into_response();
        }
    };

    let (token, _) = csrf::token(&jar);
    let page = DashboardPage {
        csrf: token.clone(),
        user_name: user.display_name,
        user_email: user.email,
        users_active: counts.users_active,
        apps_count: counts.apps_count,
        roles_count: counts.roles_count,
        permissions_count: counts.permissions_count,
        sessions_active: counts.sessions_active,
        audit_24h: counts.audit_24h,
        roles: session.claims.role.clone(),
        scope: session.claims.scope.clone(),
    };

    match render(page) {
        Ok(body) => (jar.add(csrf::cookie(token, state.config.is_prod())), body).into_response(),
        Err(err) => err.into_response(),
    }
}

/// Hasil login yang sudah lolos verifikasi kredensial.
struct IssuedSession {
    access_token: String,
    refresh_token: String,
    access_ttl: i64,
    refresh_ttl: i64,
}

/// Verifikasi kredensial lalu terbitkan sesi + access token untuk app `core`.
///
/// `None` berarti ditolak; pemanggil yang mencatat kegagalan supaya aturan rate
/// limit tetap di satu tempat.
async fn issue_console_session(
    state: &AppState,
    form: &LoginForm,
    headers: &HeaderMap,
    ip: &str,
) -> Option<IssuedSession> {
    let app = db_apps::by_slug(&state.pool, CONSOLE_APP)
        .await
        .ok()?
        .filter(|app| app.is_active)?;

    let user = db_users::by_email(&state.pool, &form.email).await.ok()??;
    if user.status != UserStatus::Active {
        return None;
    }

    let password_ok = verify_password(
        &form.password,
        &user.password_hash,
        state.config.argon2_pepper_version,
        &state.config.argon2_pepper,
    )
    .unwrap_or(false);
    if !password_ok {
        return None;
    }

    let (refresh_token, refresh_hash) = new_refresh_token();
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(MAX_USER_AGENT).collect::<String>())
        .unwrap_or_default();
    let ip = if ip == "unknown" { None } else { Some(ip) };
    let expires_at =
        OffsetDateTime::now_utc() + time::Duration::seconds(app.refresh_ttl_secs as i64);

    let session_id = sessions::insert(
        &state.pool,
        user.id,
        app.id,
        &refresh_hash,
        expires_at,
        &user_agent,
        ip,
    )
    .await
    .ok()?;

    let role = db_rbac::resolve_roles(&state.pool, user.id, app.id)
        .await
        .ok()?;
    let scope = db_rbac::resolve_scope(&state.pool, user.id, app.id)
        .await
        .ok()?;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let access_ttl = app.access_ttl_secs as i64;

    let claims = Claims {
        iss: state.config.iam_public_url.clone(),
        sub: user.id.to_string(),
        aud: app.slug.clone(),
        azp: app.id.to_string(),
        sid: session_id.to_string(),
        typ: "user".to_string(),
        role,
        scope,
        tv: user.token_version,
        jti: Uuid::now_v7().to_string(),
        iat: now,
        exp: now + access_ttl,
    };

    let access_token = match sign_access(&state.signing, &claims) {
        Ok(token) => token,
        Err(err) => {
            tracing::error!(error = %err, "gagal menandatangani access token console");
            return None;
        }
    };

    Some(IssuedSession {
        access_token,
        refresh_token,
        access_ttl,
        refresh_ttl: app.refresh_ttl_secs as i64,
    })
}

/// Render template askama jadi respons HTML. Kegagalan render = 500, bukan
/// halaman setengah jadi.
fn render<T: Template>(template: T) -> Result<Html<String>, AppError> {
    template.render().map(Html).map_err(|err| {
        tracing::error!(error = %err, "gagal merender template console");
        AppError::Internal
    })
}

/// Halaman login dengan pesan error, status sesuai jenis kegagalan.
fn login_error(
    state: &AppState,
    jar: CookieJar,
    email: &str,
    status: StatusCode,
    message: &str,
) -> Response {
    let (token, _) = csrf::token(&jar);
    let page = LoginPage {
        csrf: token.clone(),
        email: email.to_string(),
        error: Some(message.to_string()),
    };

    match render(page) {
        Ok(body) => (
            status,
            jar.add(csrf::cookie(token, state.config.is_prod())),
            body,
        )
            .into_response(),
        Err(err) => err.into_response(),
    }
}

/// 403 untuk token CSRF yang tidak cocok.
fn csrf_rejected(jar: CookieJar) -> Response {
    let page = ErrorPage {
        title: "Permintaan ditolak",
        message: "Token keamanan form tidak cocok atau sudah kedaluwarsa. \
                  Muat ulang halaman lalu coba lagi."
            .to_string(),
    };

    match render(page) {
        Ok(body) => (StatusCode::FORBIDDEN, jar, body).into_response(),
        Err(err) => err.into_response(),
    }
}

/// 303 ke halaman login, sekaligus membuang cookie yang sudah tidak sah.
fn redirect_to_login(clear_cookies: bool, secure: bool) -> Response {
    let mut response = Redirect::to("/console/login").into_response();
    if clear_cookies {
        clear_session_cookies(&mut response, secure);
    }
    response
}

/// Tambahkan dua header `Set-Cookie` yang menghapus sesi di browser.
///
/// `Secure` mengikuti lingkungan: cookie yang dipasang dengan `Secure` di
/// produksi sebaiknya dihapus lewat respons ber-flag sama, supaya perilakunya
/// konsisten di semua browser yang ketat soal atribut cookie.
fn clear_session_cookies(response: &mut Response, secure: bool) {
    let suffix = if secure { "; Secure" } else { "" };
    for value in [CLEAR_ACCESS, CLEAR_REFRESH] {
        let line = format!("{value}{suffix}");
        if let Ok(header) = header::HeaderValue::from_str(&line) {
            response.headers_mut().append(header::SET_COOKIE, header);
        }
    }
}

/// Buat refresh token acak; yang disimpan di database hanya hash-nya.
fn new_refresh_token() -> (String, String) {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::TryRngCore;

    let mut bytes = [0u8; REFRESH_BYTES];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("RNG sistem harus selalu tersedia");

    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_refresh_token(&token);
    (token, hash)
}
