//! `GET /.well-known/jwks.json`: kunci publik aktif untuk verifikasi token.

use axum::extract::State;
use axum::http::header::CACHE_CONTROL;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::state::AppState;

/// JWKS bersifat publik (tanpa auth) dan boleh di-cache sebentar oleh verifier.
const JWKS_CACHE_CONTROL: &str = "public, max-age=300";

/// Router JWKS. Dipasang di root, bukan di bawah `/api`.
pub fn router() -> Router<AppState> {
    Router::new().route("/.well-known/jwks.json", get(jwks))
}

async fn jwks(State(state): State<AppState>) -> Response {
    (
        [(CACHE_CONTROL, JWKS_CACHE_CONTROL)],
        Json(state.signing.jwks_json()),
    )
        .into_response()
}
