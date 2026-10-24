//! `POST /api/oauth/token` untuk alur `client_credentials` (mesin ke mesin).
//!
//! Endpoint ini publik dalam arti tidak memakai ekstraktor token: identitas
//! pemanggil justru dibentuk di sini dari HTTP Basic. Body yang diterima adalah
//! `application/x-www-form-urlencoded` sesuai RFC 6749; JSON juga diterima
//! supaya pengujian dan pemakaian internal tidak perlu menyusun form. Kalau
//! `Content-Type` bukan JSON, isi body selalu diperlakukan sebagai form.
//!
//! Bentuk error mengikuti OAuth (`{"error": "..."}`), bukan format error internal
//! aplikasi, karena klien alur ini adalah library OAuth standar.

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::jwt::{Claims, sign_access};
use crate::auth::secret::verify_client_secret;
use crate::db::apps::{self, App};
use crate::state::AppState;

/// Router endpoint token mesin-ke-mesin.
pub fn router() -> Router<AppState> {
    Router::new().route("/api/oauth/token", post(token))
}

/// Respons sukses sesuai RFC 6749 §5.1.
#[derive(Debug, Serialize)]
pub struct ServiceTokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub scope: String,
}

/// Terbitkan access token untuk satu client. Semua kegagalan kredensial dijawab
/// dengan pesan yang sama supaya tidak bisa dipakai menebak client_id mana yang
/// terdaftar.
async fn token(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Some((client_id, client_secret)) = basic_credentials(&headers) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };

    let grant_type = grant_type(&headers, &body);
    if grant_type.as_deref() != Some("client_credentials") {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }

    let Some(credential) = lookup(&state, &client_id).await else {
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

    let Some(app) = active_app(&state, credential.app_id).await else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };

    let claims = service_claims(&state, &app, &credential.client_id);

    let access_token = match sign_access(&state.signing, &claims) {
        Ok(token) => token,
        Err(err) => {
            tracing::error!(error = %err, "gagal menandatangani token service");
            return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
        }
    };

    // Pencatatan pemakaian bersifat informatif; kegagalannya tidak boleh
    // membatalkan token yang sudah sah ditandatangani.
    if let Err(err) = apps::touch_credential(&state.pool, credential.id).await {
        tracing::warn!(error = %err, "gagal memperbarui last_used_at kredensial");
    }

    Json(ServiceTokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: app.access_ttl_secs as i64,
        scope: String::new(),
    })
    .into_response()
}

/// Ambil `client_id` dan secret dari header `Authorization: Basic`.
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

/// Baca `grant_type` dari body. JSON dipakai kalau header memang menyebut JSON,
/// selain itu body diperlakukan sebagai form URL-encoded.
///
/// Nilai grant_type tidak pernah mengandung karakter yang perlu di-escape, jadi
/// parsing form di sini sengaja tidak melakukan percent-decoding.
fn grant_type(headers: &HeaderMap, body: &Bytes) -> Option<String> {
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase().contains("json"))
        .unwrap_or(false);

    if is_json {
        let parsed: serde_json::Value = serde_json::from_slice(body).ok()?;
        return parsed
            .get("grant_type")
            .and_then(|value| value.as_str())
            .map(str::to_string);
    }

    let body = std::str::from_utf8(body).ok()?;
    body.split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "grant_type")
        .map(|(_, value)| value.to_string())
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

/// Respons error berbentuk OAuth; sengaja tidak memuat pesan tambahan.
fn oauth_error(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}
