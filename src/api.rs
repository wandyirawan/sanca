pub mod auth;
pub mod health;
pub mod jwks;
pub mod me;

use axum::Router;

use crate::state::AppState;

/// Router API JSON: kesehatan, JWKS publik, dan endpoint auth.
///
/// Route lain (users, apps, rbac, audit) menyusul di phase berikutnya.
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(health::router())
        .merge(jwks::router())
        .merge(auth::router())
        .merge(me::router())
}
