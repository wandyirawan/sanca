//! Endpoint login, refresh (dengan rotasi), dan logout.
//!
//! Semua kegagalan login dijawab dengan satu pesan yang sama supaya penyerang
//! tidak bisa memakai respons untuk menebak email mana yang terdaftar.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::jwt::{Claims, sign_access};
use crate::auth::password::verify_password;
use crate::db::apps::{self, App};
use crate::db::users::{self, User, UserStatus};
use crate::db::{rbac, sessions};
use crate::domain::audit::{self, ActorType, Event};
use crate::error::AppError;
use crate::middleware::ratelimit::{PeerAddr, client_ip};
use crate::state::AppState;

/// Panjang refresh token mentah, dalam byte, sebelum di-encode base64url.
const REFRESH_BYTES: usize = 32;

/// Batas panjang user-agent yang disimpan; header bisa sepanjang apa saja.
const MAX_USER_AGENT: usize = 512;

/// Router endpoint auth. `me` ada di modul terpisah karena memakai ekstraktor.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/auth/refresh", post(refresh))
        .route("/api/auth/logout", post(logout))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub app_slug: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// Bentuk respons login/refresh. `expires_in` dalam detik, mengikuti access TTL app.
#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
}

/// Tukar email + password dengan sepasang token.
#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginRequest,
    responses((status = 200, description = "OK", body = TokenResponse))
)]
pub(crate) async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: PeerAddr,
    Json(body): Json<LoginRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let ip = client_ip(&headers, peer.0);

    if state.login_limiter.is_blocked(&body.email, &ip) {
        return Err(AppError::TooManyRequests);
    }

    let Some((user, app)) = check_credentials(&state, &body).await? else {
        state.login_limiter.record_failure(&body.email, &ip);
        record_login_failed(&state, &body, &headers);
        return Err(AppError::Unauthorized);
    };

    state.login_limiter.clear(&body.email, &ip);

    let (session_id, refresh_token) = start_session(&state, user.id, &app, &headers, &ip).await?;
    let (access_token, expires_in) = issue_access(&state, &user, &app, session_id).await?;

    // Login berhasil dicatat eksplisit: route ini publik, jadi middleware audit
    // tidak punya klaim token untuk dibaca saat request masuk.
    let event = Event::new(&app.slug, "auth.login", ActorType::User)
        .actor(Some(user.id))
        .app(Some(app.id))
        .request("POST", "/api/auth/login", &headers)
        .status(200);
    audit::record(&state.pool, event);

    Ok(Json(TokenResponse {
        access_token,
        refresh_token,
        token_type: "Bearer",
        expires_in,
    }))
}

/// Cek kredensial. `Ok(None)` berarti ditolak, dan pemanggil yang mencatat
/// kegagalannya supaya aturan rate limit tetap di satu tempat.
async fn check_credentials(
    state: &AppState,
    body: &LoginRequest,
) -> Result<Option<(User, App)>, AppError> {
    let Some(app) = apps::by_slug(&state.pool, &body.app_slug)
        .await?
        .filter(|app| app.is_active)
    else {
        return Ok(None);
    };

    let Some(user) = users::by_email(&state.pool, &body.email).await? else {
        return Ok(None);
    };

    if user.status != UserStatus::Active {
        return Ok(None);
    }

    match verify_password(
        &body.password,
        &user.password_hash,
        state.config.argon2_pepper_version,
        &state.config.argon2_pepper,
    ) {
        Ok(true) => Ok(Some((user, app))),
        Ok(false) => Ok(None),
        // Hash tersimpan rusak: dari luar tetap terlihat seperti kredensial salah.
        Err(err) => {
            tracing::warn!(error = %err, email = %body.email, "verifikasi password gagal");
            Ok(None)
        }
    }
}

/// Rotasi: sesi lama dicabut, sesi baru dibuat, token baru diterbitkan.
#[utoipa::path(
    post,
    path = "/api/auth/refresh",
    request_body = RefreshRequest,
    responses((status = 200, description = "OK", body = TokenResponse))
)]
pub(crate) async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    let hash = hash_refresh_token(&body.refresh_token);

    let Some(session) = sessions::by_refresh_hash(&state.pool, &hash).await? else {
        return Err(AppError::Unauthorized);
    };

    let Some(app) = apps::by_id(&state.pool, session.app_id)
        .await?
        .filter(|app| app.is_active)
    else {
        return Err(AppError::Unauthorized);
    };

    let Some(user) = users::by_id(&state.pool, session.user_id).await? else {
        return Err(AppError::Unauthorized);
    };

    if user.status != UserStatus::Active {
        return Err(AppError::Unauthorized);
    }

    // Urutan penting: cabut dulu, baru terbitkan. Kalau langkah kedua gagal,
    // pengguna harus login ulang, bukan memakai token lama dua kali.
    sessions::revoke(&state.pool, session.id).await?;

    let ip = client_ip(&headers, None);
    let (session_id, refresh_token) = start_session(&state, user.id, &app, &headers, &ip).await?;
    let (access_token, expires_in) = issue_access(&state, &user, &app, session_id).await?;

    // Rotasi sesi juga publik dari sudut pandang middleware, jadi dicatat di sini.
    let event = Event::new(&app.slug, "auth.refresh", ActorType::User)
        .actor(Some(user.id))
        .app(Some(app.id))
        .request("POST", "/api/auth/refresh", &headers)
        .status(200);
    audit::record(&state.pool, event);

    Ok(Json(TokenResponse {
        access_token,
        refresh_token,
        token_type: "Bearer",
        expires_in,
    }))
}

/// Cabut sesi milik refresh token. Selalu 204, termasuk kalau tokennya sudah
/// tidak dikenal, supaya endpoint ini tidak bisa dipakai menebak token valid.
#[utoipa::path(
    post,
    path = "/api/auth/logout",
    request_body = RefreshRequest,
    responses((status = 204, description = "No Content"))
)]
pub(crate) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RefreshRequest>,
) -> Result<StatusCode, AppError> {
    let hash = hash_refresh_token(&body.refresh_token);

    if let Some(session) = sessions::by_refresh_hash(&state.pool, &hash).await? {
        sessions::revoke(&state.pool, session.id).await?;

        // Slug app dibaca dari sesi yang dicabut supaya jejaknya terbaca;
        // kegagalan membaca app tidak boleh membatalkan logout.
        if let Ok(Some(app)) = apps::by_id(&state.pool, session.app_id).await {
            let event = Event::new(&app.slug, "auth.logout", ActorType::User)
                .actor(Some(session.user_id))
                .app(Some(app.id))
                .request("POST", "/api/auth/logout", &headers)
                .status(204);
            audit::record(&state.pool, event);
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Catat login yang ditolak. Yang disimpan hanya alasan; email, password, dan
/// body request tidak pernah ikut ke metadata.
fn record_login_failed(state: &AppState, body: &LoginRequest, headers: &HeaderMap) {
    let event = Event::new(&body.app_slug, "auth.login_failed", ActorType::User)
        .request("POST", "/api/auth/login", headers)
        .status(401)
        .metadata(serde_json::json!({ "reason": "invalid_credentials" }));

    audit::record(&state.pool, event);
}

/// Buat sesi baru dan kembalikan (id sesi, refresh token mentah).
async fn start_session(
    state: &AppState,
    user_id: Uuid,
    app: &App,
    headers: &HeaderMap,
    ip: &str,
) -> Result<(Uuid, String), AppError> {
    let (refresh_token, refresh_hash) = new_refresh_token();

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(MAX_USER_AGENT).collect::<String>())
        .unwrap_or_default();

    let expires_at =
        OffsetDateTime::now_utc() + time::Duration::seconds(app.refresh_ttl_secs as i64);

    // "unknown" berarti tidak ada info alamat sama sekali; lebih jujur disimpan
    // sebagai NULL daripada inet yang mengarang.
    let ip = if ip == "unknown" { None } else { Some(ip) };

    let session_id = sessions::insert(
        &state.pool,
        user_id,
        app.id,
        &refresh_hash,
        expires_at,
        &user_agent,
        ip,
    )
    .await?;

    Ok((session_id, refresh_token))
}

/// Susun klaim dan tandatangani access token untuk satu sesi.
async fn issue_access(
    state: &AppState,
    user: &User,
    app: &App,
    session_id: Uuid,
) -> Result<(String, i64), AppError> {
    let role = rbac::resolve_roles(&state.pool, user.id, app.id).await?;
    let scope = rbac::resolve_scope(&state.pool, user.id, app.id).await?;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let expires_in = app.access_ttl_secs as i64;

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
        exp: now + expires_in,
    };

    let token = sign_access(&state.signing, &claims).map_err(|err| {
        tracing::error!(error = %err, "gagal menandatangani access token");
        AppError::Internal
    })?;

    Ok((token, expires_in))
}

/// Buat refresh token acak 32 byte; yang disimpan di database hanya hash-nya.
fn new_refresh_token() -> (String, String) {
    let mut bytes = [0u8; REFRESH_BYTES];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("RNG sistem harus selalu tersedia");

    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_refresh_token(&token);
    (token, hash)
}

/// SHA-256 hex dari token. Cukup karena token aslinya acak 256 bit, bukan
/// password yang bisa ditebak.
fn hash_refresh_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}
