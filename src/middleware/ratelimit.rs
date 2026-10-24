//! Pembatas percobaan login gagal, disimpan di memori proses.
//!
//! Kuncinya pasangan (email, ip). Lima kegagalan dalam lima menit membuat
//! percobaan berikutnya ditolak 429 sampai jendelanya lewat. Login sukses
//! menghapus hitungan. Tidak ada Redis: satu instance, satu peta.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;

/// Jumlah kegagalan yang masih ditoleransi sebelum diblokir.
pub const MAX_FAILURES: u32 = 5;

/// Panjang jendela penghitungan.
pub const WINDOW: Duration = Duration::from_secs(300);

/// Satu catatan kegagalan: berapa kali dan sejak kapan dihitung.
struct Attempts {
    count: u32,
    first_seen: Instant,
}

/// Penghitung login gagal per (email, ip).
#[derive(Default)]
pub struct LoginLimiter {
    attempts: Mutex<HashMap<(String, String), Attempts>>,
}

impl LoginLimiter {
    /// Apakah pasangan ini sudah melewati batas dan masih di dalam jendela.
    pub fn is_blocked(&self, email: &str, ip: &str) -> bool {
        let mut map = self.lock();
        let now = Instant::now();
        purge(&mut map, now);

        map.get(&key(email, ip))
            .is_some_and(|a| a.count >= MAX_FAILURES)
    }

    /// Catat satu kegagalan; entri lama yang sudah lewat jendela dimulai ulang.
    pub fn record_failure(&self, email: &str, ip: &str) {
        let mut map = self.lock();
        let now = Instant::now();
        purge(&mut map, now);

        let entry = map.entry(key(email, ip)).or_insert(Attempts {
            count: 0,
            first_seen: now,
        });
        entry.count += 1;
    }

    /// Login berhasil: hitungan untuk pasangan ini tidak relevan lagi.
    pub fn clear(&self, email: &str, ip: &str) {
        self.lock().remove(&key(email, ip));
    }

    /// Mutex tidak menyimpan data yang bisa membuat panic di tengah update, jadi
    /// keadaan poisoned tetap aman dipakai.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(String, String), Attempts>> {
        self.attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Email dinormalisasi karena kolom `users.email` juga case-insensitive.
fn key(email: &str, ip: &str) -> (String, String) {
    (email.trim().to_lowercase(), ip.to_string())
}

/// Buang entri yang jendelanya sudah habis, supaya peta tidak tumbuh selamanya.
fn purge(map: &mut HashMap<(String, String), Attempts>, now: Instant) {
    map.retain(|_, a| now.duration_since(a.first_seen) < WINDOW);
}

/// Alamat peer TCP, kalau server dijalankan lewat `into_make_service_with_connect_info`.
///
/// Dibungkus ekstraktor sendiri karena `ConnectInfo` tidak bisa dipakai sebagai
/// `Option` di handler, dan test lewat `oneshot` memang tidak punya peer.
pub struct PeerAddr(pub Option<SocketAddr>);

impl FromRequestParts<crate::state::AppState> for PeerAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &crate::state::AppState,
    ) -> Result<Self, Self::Rejection> {
        Ok(PeerAddr(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0),
        ))
    }
}

/// IP pemanggil untuk kunci rate limit.
///
/// `X-Forwarded-For` diambil elemen pertama karena server ini berdiri di belakang
/// reverse proxy; tanpa header itu dipakai alamat koneksi TCP. Kalau keduanya
/// tidak ada (mis. dipanggil lewat `oneshot` di test), dipakai penanda tetap.
pub fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| peer.map(|addr| addr.ip().to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}
