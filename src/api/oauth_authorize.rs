//! `GET`/`POST /oauth/authorize` — halaman persetujuan OAuth2 + PKCE.
//!
//! Halaman ini milik manusia, jadi kegagalannya halaman HTML, bukan JSON: token
//! tidak pernah dibawa lewat URL pada alur ini, dan browser tidak bisa memakai
//! `{"error": "..."}`. Yang dikerjakan handler hanya tiga hal — menyiapkan data
//! untuk halaman consent, menolak permintaan yang tidak sah, dan membuat kode
//! sekali pakai setelah pengguna menekan "Izinkan". Semua aturan alur ada di
//! `domain::oauth`.
//!
//! Pertukaran kode menjadi token **tidak** ada di sini: itu phase berikutnya
//! (`POST /api/oauth/token` grant `authorization_code`). Sampai saat itu kode
//! yang tersimpan hanya bisa kedaluwarsa atau ditandai terpakai.
//!
//! Sesi console dipakai ulang apa adanya: middleware `session_gate` sudah
//! memverifikasi cookie `sanca_access` dan menaruh klaimnya di extensions, jadi
//! halaman ini tidak punya jalur login sendiri.

use askama::Template;
use axum::Extension;
use axum::Form;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum_extra::extract::CookieJar;
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::jwt::Claims;
use crate::console::ConsoleSession;
use crate::console::helpers;
use crate::console::views::ErrorPage;
use crate::db::apps::{self, App};
use crate::db::rbac as db_rbac;
use crate::db::users as db_users;
use crate::domain::oauth::{self, AuthorizeError, AuthorizeRequest};
use crate::error::AppError;
use crate::middleware::csrf;
use crate::state::AppState;

/// Router alur otorisasi. Route-nya terdaftar di `rbac::registry`.
pub fn router() -> Router<AppState> {
    Router::new().route(
        "/oauth/authorize",
        get(authorize_page).post(authorize_submit),
    )
}

/// Parameter otorisasi. Satu struct dipakai GET (query) dan POST (form) supaya
/// halaman consent dan handler yang memprosesnya tidak bisa berbeda pendapat
/// soal nama field.
///
/// `_csrf` dan `decision` hanya datang dari form; pada GET keduanya kosong.
#[derive(Debug, Default, Deserialize)]
pub struct AuthorizeParams {
    #[serde(default)]
    pub response_type: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub decision: String,
    #[serde(default)]
    pub _csrf: String,
}

impl AuthorizeParams {
    /// Bentuk yang dipakai lapisan domain. Scope dipecah di sini supaya validasi
    /// tidak perlu tahu soal format string berspasi.
    fn request(&self) -> AuthorizeRequest {
        AuthorizeRequest {
            response_type: self.response_type.trim().to_string(),
            client_id: self.client_id.trim().to_string(),
            redirect_uri: self.redirect_uri.clone(),
            scope: oauth::parse_scope(&self.scope),
            state: self.state.clone(),
            code_challenge: self.code_challenge.clone(),
            code_challenge_method: self.code_challenge_method.clone(),
        }
    }
}

/// Permintaan yang sudah lolos validasi dan siap ditampilkan atau dieksekusi.
struct Prepared {
    app: App,
    request: AuthorizeRequest,
    scopes: Vec<String>,
    user_id: Uuid,
    session_id: Uuid,
}

/// Kegagalan saat menyiapkan permintaan.
enum Problem {
    /// Ditolak dengan alasan yang aman ditampilkan ke pengguna.
    Rejected(AuthorizeError),
    /// Kesalahan kita sendiri; detailnya hanya masuk log.
    Internal,
}

/// Halaman consent. `can()` dipanggil layout/partial nav, sama seperti halaman
/// console lain.
#[derive(Template)]
#[template(path = "oauth/consent.html")]
pub struct ConsentPage {
    pub csrf: String,
    pub user_name: String,
    pub user_email: String,
    pub roles: Vec<String>,
    pub scope: Vec<String>,
    pub app_name: String,
    pub app_slug: String,
    /// `web` atau `spa`.
    pub app_kind: &'static str,
    pub redirect_uri: String,
    /// Scope yang benar-benar akan diberikan, sudah diiris dengan permission user.
    pub scopes: Vec<String>,
    pub response_type: String,
    pub client_id: String,
    pub scope_param: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

impl ConsentPage {
    /// Wrapper tipis supaya template cukup menulis `{% if can("user:read") %}`.
    pub fn can(&self, permission: &str) -> bool {
        helpers::can(&self.scope, &self.roles, permission)
    }
}

/// GET /oauth/authorize — tampilkan halaman consent.
async fn authorize_page(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    let prepared = match prepare(&state, &session.claims, &params).await {
        Ok(prepared) => prepared,
        Err(Problem::Rejected(err)) => return rejected_page(err),
        Err(Problem::Internal) => return AppError::Internal.into_response(),
    };

    // Nama pemilik sesi untuk shell console. Tanpa baris user, sesi ini tidak
    // bisa dipakai lagi: kirim ke login seperti gate sesi.
    let Ok(Some(user)) = db_users::detail(&state.pool, prepared.user_id).await else {
        return Redirect::to("/console/login").into_response();
    };

    let (token, _) = csrf::token(&jar);
    let page = ConsentPage {
        csrf: token.clone(),
        user_name: user.display_name,
        user_email: user.email,
        roles: session.claims.role.clone(),
        scope: session.claims.scope.clone(),
        app_name: prepared.app.name.clone(),
        app_slug: prepared.app.slug.clone(),
        app_kind: match prepared.app.kind {
            crate::db::apps::AppKind::Spa => "spa",
            _ => "web",
        },
        redirect_uri: prepared.request.redirect_uri.clone(),
        scopes: prepared.scopes.clone(),
        response_type: prepared.request.response_type.clone(),
        client_id: prepared.request.client_id.clone(),
        scope_param: params.scope.clone(),
        state: prepared.request.state.clone().unwrap_or_default(),
        code_challenge: prepared.request.code_challenge.clone().unwrap_or_default(),
        code_challenge_method: prepared
            .request
            .code_challenge_method
            .clone()
            .unwrap_or_default(),
    };

    match page.render() {
        Ok(body) => (
            jar.add(csrf_cookie(token, state.config.is_prod())),
            Html(body),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "gagal merender halaman consent");
            AppError::Internal.into_response()
        }
    }
}

/// POST /oauth/authorize — keputusan pengguna atas halaman consent.
///
/// Semua parameter divalidasi ulang dari nol. Field tersembunyi di form hanya
/// membawa niat pengguna, bukan bukti: kalau app berubah di antara GET dan POST,
/// permintaan ini ditolak dengan aturan yang sama seperti GET.
async fn authorize_submit(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
    Form(params): Form<AuthorizeParams>,
) -> Response {
    if !csrf::matches(&jar, &params._csrf) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Permintaan ditolak",
            "Token keamanan form tidak cocok atau sudah kedaluwarsa. \
             Muat ulang halaman lalu coba lagi."
                .to_string(),
        );
    }

    let prepared = match prepare(&state, &session.claims, &params).await {
        Ok(prepared) => prepared,
        Err(Problem::Rejected(err)) => return rejected_page(err),
        Err(Problem::Internal) => return AppError::Internal.into_response(),
    };

    let state_param = prepared.request.state.as_deref();

    if params.decision != "allow" {
        // `deny` (dan nilai tak dikenal) diperlakukan sama: pengguna tidak
        // memberi izin, dan client tetap harus tahu lewat redirect yang sah.
        let mut query = vec![("error", "access_denied")];
        if let Some(value) = state_param {
            query.push(("state", value));
        }
        let target = oauth::append_query(&prepared.request.redirect_uri, &query);
        return Redirect::to(&target).into_response();
    }

    let grant = oauth::CodeGrant {
        app_id: prepared.app.id,
        user_id: prepared.user_id,
        session_id: prepared.session_id,
        redirect_uri: &prepared.request.redirect_uri,
        scope: &prepared.scopes,
        code_challenge: prepared.request.code_challenge.as_deref(),
        challenge_method: prepared.request.code_challenge_method.as_deref(),
    };
    let code = match oauth::issue_code(&state.pool, &grant).await {
        Ok(code) => code,
        Err(err) => return err.into_response(),
    };

    let mut query = vec![("code", code.as_str())];
    if let Some(value) = state_param {
        query.push(("state", value));
    }
    let target = oauth::append_query(&prepared.request.redirect_uri, &query);
    Redirect::to(&target).into_response()
}

/// Cari app, validasi permintaan, lalu hitung scope yang diberikan.
async fn prepare(
    state: &AppState,
    claims: &Claims,
    params: &AuthorizeParams,
) -> Result<Prepared, Problem> {
    let request = params.request();

    if request.client_id.is_empty() {
        return Err(Problem::Rejected(AuthorizeError {
            code: "invalid_request",
            description: "parameter client_id wajib diisi".to_string(),
        }));
    }

    // `client_id` adalah kredensial, bukan slug app. Nilainya berasal dari
    // tabel `app_credentials`; slug hanya dipakai sebagai awalan saat kredensial
    // diterbitkan. Mencari app langsung lewat slug akan menolak client yang sah,
    // karena `uji-oauth6` dan `uji-oauth6-fd4a7b150682` adalah dua hal berbeda.
    let credential = apps::credential_by_client_id(&state.pool, &request.client_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "gagal mencari kredensial client untuk authorize");
            Problem::Internal
        })?;

    // Kredensial yang tidak ada dan app yang tidak aktif dijawab dengan pesan
    // yang sama, supaya tidak bisa dipakai menebak client_id mana yang terdaftar.
    let app = match credential {
        Some(credential) => apps::by_id(&state.pool, credential.app_id)
            .await
            .map_err(|err| {
                tracing::error!(error = %err, "gagal mencari app dari kredensial client");
                Problem::Internal
            })?
            .filter(|app| app.is_active),
        None => None,
    }
    .ok_or_else(|| {
        Problem::Rejected(AuthorizeError {
            code: "invalid_request",
            description: "client_id tidak dikenal".to_string(),
        })
    })?;

    oauth::validate_authorize(&app, &request).map_err(Problem::Rejected)?;

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| {
        tracing::error!("klaim sub sesi console bukan uuid");
        Problem::Internal
    })?;
    let session_id = Uuid::parse_str(&claims.sid).map_err(|_| {
        tracing::error!("klaim sid sesi console bukan uuid");
        Problem::Internal
    })?;

    let available = db_rbac::resolve_scope(&state.pool, user_id, app.id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "gagal menghitung scope user untuk app tujuan");
            Problem::Internal
        })?;

    let scopes = oauth::granted_scopes(&available, &request.scope).map_err(Problem::Rejected)?;

    Ok(Prepared {
        app,
        request,
        scopes,
        user_id,
        session_id,
    })
}

/// Halaman 400 untuk permintaan yang tidak sah. Sengaja tidak redirect: URI
/// tujuan belum tentu milik client yang sah.
fn rejected_page(err: AuthorizeError) -> Response {
    error_page(
        StatusCode::BAD_REQUEST,
        "Permintaan otorisasi ditolak",
        format!("{} (kode: {}).", err.description, err.code),
    )
}

/// Halaman error berdiri sendiri dengan status tertentu.
fn error_page(status: StatusCode, title: &'static str, message: String) -> Response {
    let page = ErrorPage { title, message };
    match page.render() {
        Ok(body) => (status, Html(body)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "gagal merender halaman error");
            AppError::Internal.into_response()
        }
    }
}

/// Cookie CSRF ber-path `/`.
///
/// Cookie bawaan console ber-path `/console`, sedangkan halaman consent hidup di
/// `/oauth/authorize`; dengan path lama browser tidak akan mengirim tokennya ke
/// form consent. Nilainya tetap dari `csrf::token`, jadi pemeriksaan CSRF-nya
/// tidak berubah — hanya jangkauan cookie-nya yang diperluas.
fn csrf_cookie(token: String, secure: bool) -> Cookie<'static> {
    Cookie::build((csrf::COOKIE_NAME, token))
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(false)
        .secure(secure)
        .build()
}
