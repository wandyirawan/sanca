//! State bersama yang dipegang seluruh handler.
//!
//! Hanya berisi hal yang memang dipakai lintas route: pool database, config,
//! signing key aktif, dan penghitung login gagal. Tidak ada cache atau layer
//! tambahan di sini.

use std::sync::Arc;

use sqlx::PgPool;

use crate::auth::keys::SigningKey;
use crate::config::Config;
use crate::middleware::ratelimit::LoginLimiter;

/// Bagian aplikasi yang hidup selama proses berjalan.
///
/// `Clone` murah karena semuanya `Arc` atau handle pool, jadi aman dipakai
/// sebagai `with_state` pada router.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub signing: Arc<SigningKey>,
    pub login_limiter: Arc<LoginLimiter>,
}

impl AppState {
    /// Rakit state baru dengan penghitung login yang masih kosong.
    pub fn new(pool: PgPool, config: Config, signing: SigningKey) -> Self {
        Self {
            pool,
            config: Arc::new(config),
            signing: Arc::new(signing),
            login_limiter: Arc::new(LoginLimiter::default()),
        }
    }
}
