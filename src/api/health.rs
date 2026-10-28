use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use utoipa::ToSchema;

use crate::state::AppState;

/// Route kesehatan: dipakai healthcheck container dan probe eksternal.
pub fn router() -> Router<AppState> {
    Router::new().route("/healthz", get(healthz))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: &'static str,
}

/// Kesehatan service.
#[utoipa::path(
    get,
    path = "/healthz",
    responses((status = 200, description = "OK", body = HealthResponse))
)]
pub(crate) async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}
