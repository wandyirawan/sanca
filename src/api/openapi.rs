use axum::Router;
use utoipa_swagger_ui::SwaggerUi;

use crate::state::AppState;

/// Router dokumentasi OpenAPI + Swagger UI.
pub fn router() -> Router<AppState> {
    Router::new().merge(SwaggerUi::new("/docs").url("/openapi.json", crate::openapi::openapi()))
}
