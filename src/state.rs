//! State bersama yang dipegang seluruh handler.
//!
//! Hanya berisi hal yang memang dipakai lintas route: pool database, config,
//! keyset signing (satu penanda tangan aktif plus verifier kunci lama), dan
//! penghitung login gagal. Tidak ada cache atau layer tambahan di sini.

use std::sync::Arc;

use sqlx::PgPool;

use crate::auth::keys::KeySet;
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
    pub signing: Arc<KeySet>,
    pub login_limiter: Arc<LoginLimiter>,
}

impl AppState {
    /// Rakit state baru dengan penghitung login yang masih kosong.
    ///
    /// Menerima `KeySet` maupun `SigningKey` tunggal; yang kedua dibungkus jadi
    /// keyset satu kunci supaya pemanggil lama tidak perlu berubah.
    pub fn new(pool: PgPool, config: Config, signing: impl Into<KeySet>) -> Self {
        Self {
            pool,
            config: Arc::new(config),
            signing: Arc::new(signing.into()),
            login_limiter: Arc::new(LoginLimiter::default()),
        }
    }
}
