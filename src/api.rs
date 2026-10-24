pub mod health;

use axum::Router;

/// Router API JSON. Untuk sekarang hanya berisi route kesehatan; area lain
/// (auth, users, apps, rbac, audit) menyusul di phase berikutnya.
pub fn router() -> Router {
    health::router()
}
