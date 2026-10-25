//! `POST /api/oauth/token` untuk tiga alur: `client_credentials` (mesin ke
//! mesin), `authorization_code` (manusia lewat halaman consent), dan
//! `refresh_token` (perpanjangan sesi).
//!
//! Endpoint ini publik dalam arti tidak memakai ekstraktor token: identitas
//! pemanggil justru dibentuk di sini dari HTTP Basic dan/atau parameter body.
//! Body yang diterima adalah `application/x-www-form-urlencoded` sesuai RFC 6749;
//! JSON juga diterima supaya pengujian dan pemakaian internal tidak perlu
//! menyusun form. Kalau `Content-Type` bukan JSON, isi body selalu diperlakukan
//! sebagai form.
//!
//! Bentuk error mengikuti OAuth (`{"error": "..."}`), bukan format error internal
//! aplikasi, karena klien alur ini adalah library OAuth standar. Semua respons —
//! sukses maupun gagal — membawa `Cache-Control: no-store` (RFC 6749 §5.1).
//!
//! Aturan yang menentukan keamanan tiap grant ada di `domain::oauth`; handler di
//! sini hanya membaca parameter, memverifikasi kredensial client, lalu menyusun
//! respons.

use std::collections::HashMap;

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::jwt::{Claims, sign_access};
use crate::auth::secret::verify_client_secret;
use crate::db::apps::{self, App, AppKind};
use crate::db::rbac as db_rbac;
use crate::db::users::{self, User, UserStatus};
use crate::domain::audit::{self, ActorType, Event};
use crate::domain::oauth::{self, GrantError};
use crate::middleware::ratelimit::client_ip;
use crate::state::AppState;

/// Router endpoint token OAuth.
pub fn router() -> Router<AppState> {
    Router::new().route("/api/oauth/token", post(token))
}

/// Respons sukses sesuai RFC 6749 §5.1.
///
/// `refresh_token` hanya diisi oleh dua grant yang punya sesi; pada
/// `client_credentials` field-nya tidak dikirim sama sekali supaya bentuk respons
/// lama tidak berubah.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Titik masuk: pilih grant, lalu tempelkan `Cache-Control: no-store`.
///
/// Header dipasang di satu tempat supaya jalur error tidak bisa lupa. Respons
/// token berisi kredensial berumur pendek; cache perantara tidak boleh menyimpannya.
async fn token(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let mut response = dispatch(&state, &headers, &body).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Arahkan permintaan ke grant yang diminta. Grant tak dikenal dijawab
/// `unsupported_grant_type`, termasuk kalau `grant_type` tidak dikirim.
async fn dispatch(state: &AppState, headers: &HeaderMap, body: &Bytes) -> Response {
    let params = Params::parse(headers, body);

    match params.get("grant_type") {
        Some("client_credentials") => client_credentials(state, headers).await,
        Some("authorization_code") => authorization_code(state, headers, &params).await,
        Some("refresh_token") => refresh_grant(state, headers, &params).await,
        _ => oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
}

/// Grant mesin-ke-mesin: hanya HTTP Basic, tanpa user dan tanpa sesi.
async fn client_credentials(state: &AppState, headers: &HeaderMap) -> Response {
    let Some((client_id, client_secret)) = basic_credentials(headers) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };

    let Some(credential) = lookup(state, &client_id).await else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };

    match verify_client_secret(
        &client_secret,
        &credential.client_secret_hash,
        &state.config.client_secret_pepper,
    ) {
        Ok(true) => {}
        Ok(false) => return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client"),
        Err(err) => {
            tracing::error!(error = %err, "verifikasi secret client gagal");
            return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
        }
    }

    let Some(app) = active_app(state, credential.app_id).await else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };

    let claims = service_claims(state, &app, &credential.client_id);

    let Some(access_token) = sign_token(state, &claims) else {
        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };

    // Pencatatan pemakaian bersifat informatif; kegagalannya tidak boleh
    // membatalkan token yang sudah sah ditandatangani.
    touch(state, credential.id).await;

    // Route token publik bagi middleware, jadi penerbitan token dicatat eksplisit.
    let event = Event::new(&app.slug, "token.client_credentials", ActorType::Service)
        .app(Some(app.id))
        .request("POST", "/api/oauth/token", headers)
        .status(200);
    audit::record(&state.pool, event);

    token_response(access_token, app.access_ttl_secs as i64, &[], None)
}

/// Grant `authorization_code`: kode sekali pakai + PKCE.
async fn authorization_code(state: &AppState, headers: &HeaderMap, params: &Params) -> Response {
    let (app, credential) = match client_of_public_flow(state, headers, params).await {
        Ok(found) => found,
        Err(rejection) => return client_rejection(rejection),
    };

    let Some(code) = params.get("code") else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    // redirect_uri wajib ikut dan harus sama dengan yang terikat di baris kode.
    let Some(redirect_uri) = params.get("redirect_uri") else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };

    let (user_agent, ip) = client_context(headers);
    let exchanged = match oauth::exchange_code(
        &state.pool,
        &app,
        code,
        redirect_uri,
        params.get("code_verifier"),
        &user_agent,
        ip.as_deref(),
    )
    .await
    {
        Ok(exchanged) => exchanged,
        Err(GrantError::InvalidGrant) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
        }
        Err(GrantError::Internal) => {
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };

    touch(state, credential.id).await;

    // Klaim user memakai data terkini: token_version dan role dibaca ulang,
    // bukan disalin dari kode, supaya user yang dinonaktifkan atau dicabut
    // role-nya tidak mendapat token lama yang masih berlaku.
    let Some(user) = active_user(state, exchanged.user_id).await else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };

    let Some(role) = resolve_roles(state, user.id, app.id).await else {
        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };

    let claims = user_claims(state, &app, &user, exchanged.sid, role, exchanged.scope);
    let Some(access_token) = sign_token(state, &claims) else {
        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };

    let event = Event::new(&app.slug, "token.authorization_code", ActorType::User)
        .actor(Some(user.id))
        .app(Some(app.id))
        .request("POST", "/api/oauth/token", headers)
        .status(200);
    audit::record(&state.pool, event);

    token_response(
        access_token,
        app.access_ttl_secs as i64,
        &claims.scope,
        Some(exchanged.refresh_token),
    )
}

/// Grant `refresh_token`: rotasi sesi, scope dan role dihitung ulang.
async fn refresh_grant(state: &AppState, headers: &HeaderMap, params: &Params) -> Response {
    let (app, credential) = match client_of_public_flow(state, headers, params).await {
        Ok(found) => found,
        Err(rejection) => return client_rejection(rejection),
    };

    let Some(refresh_token) = params.get("refresh_token") else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    };

    let (user_agent, ip) = client_context(headers);
    let rotated =
        match oauth::rotate_refresh(&state.pool, &app, refresh_token, &user_agent, ip.as_deref())
            .await
        {
            Ok(rotated) => rotated,
            Err(GrantError::InvalidGrant) => {
                return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            Err(GrantError::Internal) => {
                return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
            }
        };

    touch(state, credential.id).await;

    let Some(user) = active_user(state, rotated.user_id).await else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };

    let Some(role) = resolve_roles(state, user.id, app.id).await else {
        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    let scope = match db_rbac::resolve_scope(&state.pool, user.id, app.id).await {
        Ok(scope) => scope,
        Err(err) => {
            tracing::error!(error = %err, "gagal menghitung scope saat refresh");
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };

    let claims = user_claims(state, &app, &user, rotated.sid, role, scope);
    let Some(access_token) = sign_token(state, &claims) else {
        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };

    let event = Event::new(&app.slug, "token.refresh_token", ActorType::User)
        .actor(Some(user.id))
        .app(Some(app.id))
        .request("POST", "/api/oauth/token", headers)
        .status(200);
    audit::record(&state.pool, event);

    token_response(
        access_token,
        app.access_ttl_secs as i64,
        &claims.scope,
        Some(rotated.refresh_token),
    )
}

/// Parameter body token, sudah di-decode dari form atau JSON.
///
/// Nama field OAuth tidak peka huruf besar/kecil di lapangan, tetapi RFC 6749
/// menuliskannya huruf kecil semua; yang diterima di sini persis nama RFC agar
/// tidak ada dua ejaan yang berarti sama.
struct Params(HashMap<String, String>);

impl Params {
    fn parse(headers: &HeaderMap, body: &Bytes) -> Self {
        let is_json = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_ascii_lowercase().contains("json"))
            .unwrap_or(false);

        if is_json {
            let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
            let mut map = HashMap::new();
            if let Some(object) = parsed.as_object() {
                for (key, value) in object {
                    if let Some(text) = value.as_str() {
                        map.insert(key.clone(), text.to_string());
                    }
                }
            }
            return Self(map);
        }

        let mut map = HashMap::new();
        if let Ok(body) = std::str::from_utf8(body) {
            for pair in body.split('&').filter(|pair| !pair.is_empty()) {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                map.insert(oauth::decode_component(key), oauth::decode_component(value));
            }
        }
        Self(map)
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
}

/// Penolakan pada pemeriksaan kredensial client.
///
/// Sengaja berupa kode sempit, bukan `Response`, supaya handler yang memutuskan
/// status HTTP dan tidak ada alokasi besar di jalur error.
enum ClientRejection {
    /// `client_id` tidak dikirim.
    InvalidRequest,
    /// Kredensial tidak dikenal, app tidak aktif, atau secret salah/hilang.
    InvalidClient,
}

/// Kredensial client untuk dua grant yang melibatkan manusia.
///
/// `client_id` datang dari body (parameter, bukan slug app). `client_secret`
/// boleh lewat HTTP Basic atau field body. Aturan siapa yang wajib membuktikan
/// diri ditentukan jenis app:
/// - `web` adalah klien rahasia, jadi secret wajib dan harus cocok;
/// - `spa` adalah klien publik (PKCE yang melindunginya), jadi secret tidak wajib.
///
/// `service`/`cli` tidak ditolak di sini: keduanya sudah tidak punya redirect_uri
/// terdaftar untuk alur ini, dan menolak di lapisan kredensial akan mengaburkan
/// alasan sebenarnya.
async fn client_of_public_flow(
    state: &AppState,
    headers: &HeaderMap,
    params: &Params,
) -> Result<(App, apps::Credential), ClientRejection> {
    let Some(client_id) = params.get("client_id").filter(|value| !value.is_empty()) else {
        return Err(ClientRejection::InvalidRequest);
    };

    let basic = basic_credentials(headers);
    let secret = params
        .get("client_secret")
        .map(str::to_string)
        .or_else(|| basic.map(|(_, secret)| secret));

    let Some(credential) = lookup(state, client_id).await else {
        return Err(ClientRejection::InvalidClient);
    };

    let Some(app) = active_app(state, credential.app_id).await else {
        return Err(ClientRejection::InvalidClient);
    };

    if app.kind == AppKind::Web {
        let Some(secret) = secret else {
            return Err(ClientRejection::InvalidClient);
        };

        match verify_client_secret(
            &secret,
            &credential.client_secret_hash,
            &state.config.client_secret_pepper,
        ) {
            Ok(true) => {}
            Ok(false) => return Err(ClientRejection::InvalidClient),
            Err(err) => {
                tracing::error!(error = %err, "verifikasi secret client gagal");
                return Err(ClientRejection::InvalidClient);
            }
        }
    }

    Ok((app, credential))
}

/// Terjemahkan penolakan kredensial menjadi respons OAuth.
fn client_rejection(rejection: ClientRejection) -> Response {
    match rejection {
        ClientRejection::InvalidRequest => oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
        ClientRejection::InvalidClient => oauth_error(StatusCode::UNAUTHORIZED, "invalid_client"),
    }
}

/// Ambil `client_id` dan secret dari header `Authorization: Basic ...`.
///
/// Skema dibandingkan tanpa peduli huruf besar/kecil, tapi isinya wajib base64
/// standar dengan satu titik dua pemisah. Bentuk apa pun yang menyimpang
/// menghasilkan `None`, bukan error terpisah.
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }

    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (client_id, client_secret) = decoded.split_once(':')?;

    if client_id.is_empty() || client_secret.is_empty() {
        return None;
    }

    Some((client_id.to_string(), client_secret.to_string()))
}

/// Cari kredensial hidup; kegagalan database diperlakukan seperti kredensial
/// tidak dikenal supaya tidak ada jalur yang membocorkan status internal.
async fn lookup(state: &AppState, client_id: &str) -> Option<apps::Credential> {
    match apps::credential_by_client_id(&state.pool, client_id).await {
        Ok(found) => found,
        Err(err) => {
            tracing::error!(error = %err, "query kredensial gagal");
            None
        }
    }
}

/// App harus masih aktif; app yang dinonaktifkan tidak boleh menerbitkan token.
async fn active_app(state: &AppState, app_id: Uuid) -> Option<App> {
    match apps::by_id(&state.pool, app_id).await {
        Ok(found) => found.filter(|app| app.is_active),
        Err(err) => {
            tracing::error!(error = %err, "query app untuk token gagal");
            None
        }
    }
}

/// User pemilik token harus masih bisa login. User yang dinonaktifkan tidak
/// mendapat access token baru, walau kode atau refresh token-nya masih muda.
async fn active_user(state: &AppState, user_id: Uuid) -> Option<User> {
    match users::by_id(&state.pool, user_id).await {
        Ok(found) => found.filter(|user| user.status == UserStatus::Active),
        Err(err) => {
            tracing::error!(error = %err, "query user untuk token gagal");
            None
        }
    }
}

/// Role user di app tujuan saja; kegagalan database jadi 500, bukan token kosong.
async fn resolve_roles(state: &AppState, user_id: Uuid, app_id: Uuid) -> Option<Vec<String>> {
    match db_rbac::resolve_roles(&state.pool, user_id, app_id).await {
        Ok(role) => Some(role),
        Err(err) => {
            tracing::error!(error = %err, "gagal menghitung role untuk token");
            None
        }
    }
}

/// `user_agent` yang dipotong dan alamat klien, dipakai saat membuat baris sesi.
///
/// `client_ip` mengembalikan `"unknown"` kalau tidak ada header yang bisa
/// dipercaya; itu disimpan sebagai NULL, bukan alamat karangan.
fn client_context(headers: &HeaderMap) -> (String, Option<String>) {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(512).collect::<String>())
        .unwrap_or_default();

    let ip = client_ip(headers, None);
    let ip = (ip != "unknown").then_some(ip);

    (user_agent, ip)
}

/// Susun klaim token service: tidak ada user, tidak ada sesi, tidak ada role.
///
/// `sub` adalah client_id karena itu identitas yang benar-benar diverifikasi,
/// sedangkan `aud` tetap slug app supaya verifikasi per app berjalan sama
/// seperti token user.
fn service_claims(state: &AppState, app: &App, client_id: &str) -> Claims {
    let now = OffsetDateTime::now_utc().unix_timestamp();

    Claims {
        iss: state.config.iam_public_url.clone(),
        sub: client_id.to_string(),
        aud: app.slug.clone(),
        azp: app.id.to_string(),
        sid: String::new(),
        typ: "service".to_string(),
        role: Vec::new(),
        scope: Vec::new(),
        tv: 0,
        jti: Uuid::now_v7().to_string(),
        iat: now,
        exp: now + app.access_ttl_secs as i64,
    }
}

/// Susun klaim access token untuk manusia: `sub` user, `sid` sesi, `typ` user.
fn user_claims(
    state: &AppState,
    app: &App,
    user: &User,
    sid: Uuid,
    role: Vec<String>,
    scope: Vec<String>,
) -> Claims {
    let now = OffsetDateTime::now_utc().unix_timestamp();

    Claims {
        iss: state.config.iam_public_url.clone(),
        sub: user.id.to_string(),
        aud: app.slug.clone(),
        azp: app.id.to_string(),
        sid: sid.to_string(),
        typ: "user".to_string(),
        role,
        scope,
        tv: user.token_version,
        jti: Uuid::now_v7().to_string(),
        iat: now,
        exp: now + app.access_ttl_secs as i64,
    }
}

/// Tandatangani klaim; `None` berarti kegagalan signing (dijawab 500 oleh
/// pemanggil) dan detailnya hanya masuk log.
fn sign_token(state: &AppState, claims: &Claims) -> Option<String> {
    match sign_access(&state.signing, claims) {
        Ok(token) => Some(token),
        Err(err) => {
            tracing::error!(error = %err, "gagal menandatangani access token");
            None
        }
    }
}

/// Bentuk respons sukses untuk ketiga grant.
fn token_response(
    access_token: String,
    expires_in: i64,
    scope: &[String],
    refresh_token: Option<String>,
) -> Response {
    Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        scope: scope.join(" "),
        refresh_token,
    })
    .into_response()
}

/// Catat pemakaian kredensial; kegagalannya hanya dicatat di log.
async fn touch(state: &AppState, credential_id: Uuid) {
    if let Err(err) = apps::touch_credential(&state.pool, credential_id).await {
        tracing::warn!(error = %err, "gagal memperbarui last_used_at kredensial");
    }
}

/// Respons error berbentuk OAuth; sengaja tidak memuat pesan tambahan.
fn oauth_error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}
