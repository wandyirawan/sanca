//! Ekstraktor autentikasi: mengubah hasil verifikasi middleware menjadi identitas.
//!
//! App pemilik request ditentukan registry route (`MatchedPath`), bukan header
//! dari klien. Middleware `rbac::enforce` yang memverifikasi token lalu menyimpan
//! hasilnya di request extensions; ekstraktor di sini hanya membacanya supaya
//! verifikasi tidak terjadi dua kali.

use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use crate::auth::jwt::{Claims, verify_access};
use crate::db::apps::{self, App};
use crate::error::AppError;
use crate::state::AppState;

/// Hasil verifikasi token yang dititipkan middleware ke request extensions.
#[derive(Debug, Clone)]
pub struct Authenticated {
    pub claims: Claims,
    pub app: App,
}

/// Pemanggil bertipe `user`. Dipakai route yang butuh login manusia.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub claims: Claims,
    pub app: App,
}

/// Pemanggil bertipe `service` (client credentials). Belum dipakai route mana pun
/// di phase ini, tapi dipisah supaya route service nanti tidak memakai AuthUser.
#[derive(Debug, Clone)]
pub struct AuthApp {
    pub claims: Claims,
    pub app: App,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &AppState) -> Result<Self, AppError> {
        let auth = part_identity(parts)?;
        if auth.claims.typ != "user" {
            return Err(AppError::Forbidden);
        }
        Ok(AuthUser {
            claims: auth.claims,
            app: auth.app,
        })
    }
}

impl FromRequestParts<AppState> for AuthApp {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &AppState) -> Result<Self, AppError> {
        let auth = part_identity(parts)?;
        if auth.claims.typ != "service" {
            return Err(AppError::Forbidden);
        }
        Ok(AuthApp {
            claims: auth.claims,
            app: auth.app,
        })
    }
}

/// Ambil identitas hasil middleware; tanpa itu berarti route tidak melewati
/// penegakan registry, jadi request dianggap tidak terautentikasi.
fn part_identity(parts: &Parts) -> Result<Authenticated, AppError> {
    parts
        .extensions
        .get::<Authenticated>()
        .cloned()
        .ok_or(AppError::Unauthorized)
}

/// Verifikasi token terhadap satu app (`expected_aud` = slug app pemilik route).
///
/// Dipanggil hanya oleh middleware. App dicari dari slug registry, bukan dari
/// header klien, jadi token milik app lain selalu ditolak 401.
pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    expected_aud: &str,
) -> Result<Authenticated, AppError> {
    let token = bearer_token(headers)?;

    let app = apps::by_slug(&state.pool, expected_aud)
        .await?
        .filter(|app| app.is_active)
        .ok_or(AppError::Unauthorized)?;

    let claims = verify_access(&state.config, &state.signing, token, &app.slug)
        .map_err(|_| AppError::Unauthorized)?;

    Ok(Authenticated { claims, app })
}

/// Ambil token dari `Authorization: Bearer ***
fn bearer_token(headers: &HeaderMap) -> Result<&str, AppError> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or(AppError::Unauthorized)
}
