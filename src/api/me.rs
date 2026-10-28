//! `GET /api/auth/me`: identitas pemilik token yang sedang dipakai.

use axum::Json;
use axum::Router;
use axum::routing::get;
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::extractor::AuthUser;
use crate::state::AppState;

/// Router endpoint identitas.
pub fn router() -> Router<AppState> {
    Router::new().route("/api/auth/me", get(me))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MeResponse {
    pub sub: String,
    pub app: String,
    pub typ: String,
    pub roles: Vec<String>,
    pub scope: Vec<String>,
}

/// Ringkasan identitas: subjek, app pemilik token, tipe, role, dan scope.
/// Isinya diambil dari klaim yang sudah diverifikasi, bukan query ulang.
#[utoipa::path(
    get,
    path = "/api/auth/me",
    responses((status = 200, description = "OK", body = MeResponse))
)]
pub(crate) async fn me(user: AuthUser) -> Json<MeResponse> {
    Json(MeResponse {
        sub: user.claims.sub,
        app: user.claims.aud,
        typ: user.claims.typ,
        roles: user.claims.role,
        scope: user.claims.scope,
    })
}
