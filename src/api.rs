pub mod auth;
pub mod console;
pub mod health;
pub mod jwks;
pub mod me;
pub mod rbac;
pub mod token;
pub mod users;

use axum::Router;

use crate::state::AppState;

/// Router API JSON: kesehatan, JWKS publik, endpoint auth, dan RBAC minimal.
///
/// Route users, apps, dan audit menyusul di phase berikutnya. Setiap route di
/// sini wajib terdaftar di `crate::rbac::registry`; middleware enforcement
/// menolak dengan 500 kalau ada yang terlewat.
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(health::router())
        .merge(jwks::router())
        .merge(auth::router())
        .merge(me::router())
        .merge(token::router())
        .merge(rbac::router())
        .merge(users::router())
        .merge(console::router())
}
