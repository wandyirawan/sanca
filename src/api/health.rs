use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

/// Route kesehatan: dipakai healthcheck container dan probe eksternal.
pub fn router() -> Router {
    Router::new().route("/healthz", get(healthz))
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
