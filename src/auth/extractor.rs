//! Ekstraktor autentikasi: mengubah header `Authorization` menjadi identitas.
//!
//! App yang diharapkan ditentukan klien lewat header `X-Sanca-App` (slug app).
//! Slug itu bukan rahasia dan bukan sumber otorisasi: token tetap diverifikasi
//! dengan `aud` = slug tersebut, jadi token milik app lain selalu ditolak 401.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use crate::auth::jwt::{Claims, verify_access};
use crate::db::apps::{self, App};
use crate::error::AppError;
use crate::state::AppState;

/// Header yang menyebut app pemilik request.
pub const APP_HEADER: &str = "x-sanca-app";

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

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let (claims, app) = authenticate(parts, state).await?;
        if claims.typ != "user" {
            return Err(AppError::Forbidden);
        }
        Ok(AuthUser { claims, app })
    }
}

impl FromRequestParts<AppState> for AuthApp {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let (claims, app) = authenticate(parts, state).await?;
        if claims.typ != "service" {
            return Err(AppError::Forbidden);
        }
        Ok(AuthApp { claims, app })
    }
}

/// Baca token, cari app dari header, lalu verifikasi tanda tangan + aud + iss.
async fn authenticate(parts: &Parts, state: &AppState) -> Result<(Claims, App), AppError> {
    let token = bearer_token(parts)?;
    let slug = app_slug(parts)?;

    let app = apps::by_slug(&state.pool, &slug)
        .await?
        .filter(|app| app.is_active)
        .ok_or(AppError::Unauthorized)?;

    let claims = verify_access(&state.config, &state.signing, token, &app.slug)
        .map_err(|_| AppError::Unauthorized)?;

    Ok((claims, app))
}

/// Ambil token dari `Authorization: Bearer <token>`.
fn bearer_token(parts: &Parts) -> Result<&str, AppError> {
    parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or(AppError::Unauthorized)
}

/// Ambil slug app dari header; tanpa header request tidak bisa diverifikasi.
fn app_slug(parts: &Parts) -> Result<String, AppError> {
    parts
        .headers
        .get(APP_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::BadRequest(format!("header {APP_HEADER} wajib diisi")))
}
