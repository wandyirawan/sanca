//! `GET /api/auth/me`: identitas pemilik token yang sedang dipakai.

use axum::Json;
use axum::Router;
use axum::routing::get;
use serde_json::{Value, json};

use crate::auth::extractor::AuthUser;
use crate::state::AppState;

/// Router endpoint identitas.
pub fn router() -> Router<AppState> {
    Router::new().route("/api/auth/me", get(me))
}

/// Ringkasan identitas: subjek, app pemilik token, tipe, role, dan scope.
/// Isinya diambil dari klaim yang sudah diverifikasi, bukan query ulang.
async fn me(user: AuthUser) -> Json<Value> {
    Json(json!({
        "sub": user.claims.sub,
        "app": user.claims.aud,
        "typ": user.claims.typ,
        "roles": user.claims.role,
        "scope": user.claims.scope,
    }))
}
