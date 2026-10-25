//! Token CSRF untuk form console (double-submit cookie).
//!
//! Token disimpan di cookie non-`httpOnly` `sanca_csrf` dan dikirim ulang di
//! hidden field `_csrf`. Penyerang yang bisa memicu POST lintas situs tidak bisa
//! membaca cookie itu (SameSite=Lax + asal berbeda), jadi ketidakcocokan berarti
//! form bukan berasal dari halaman kita.
//!
//! Token tidak pernah ditandatangani: nilainya acak 256 bit dan tidak membawa
//! identitas apa pun, jadi yang perlu dijaga hanya kerahasiaan dan kesamaan.

use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::TryRngCore;

/// Nama cookie pembawa token.
pub const COOKIE_NAME: &str = "sanca_csrf";

/// Nama field tersembunyi di setiap form console.
pub const FIELD_NAME: &str = "_csrf";

/// Panjang token mentah. 32 byte cukup untuk ditebak pun tidak.
const TOKEN_BYTES: usize = 32;

/// Token yang sudah ada di cookie, atau token baru kalau belum ada.
///
/// Nilai kedua menandakan cookie perlu dipasang di respons ini; memanggil ulang
/// di setiap GET tanpa itu akan memaksa browser menyimpan cookie baru terus.
pub fn token(jar: &CookieJar) -> (String, bool) {
    match jar.get(COOKIE_NAME) {
        Some(existing) if !existing.value().is_empty() => (existing.value().to_string(), false),
        _ => (fresh_token(), true),
    }
}

/// Cookie pembawa token. Sengaja tidak `httpOnly`: skrip tema di browser tidak
/// membacanya, tapi form yang dirender HTMX butuh nilai ini tersedia.
pub fn cookie(token: String) -> Cookie<'static> {
    Cookie::build((COOKIE_NAME, token))
        .path("/console")
        .same_site(SameSite::Lax)
        .http_only(false)
        .build()
}

/// Bandingkan token yang dikirim form dengan yang ada di cookie.
///
/// Perbandingan constant-time supaya lama proses tidak membocorkan berapa
/// karakter awal yang sudah cocok.
pub fn matches(jar: &CookieJar, submitted: &str) -> bool {
    let Some(expected) = jar.get(COOKIE_NAME).map(Cookie::value) else {
        return false;
    };

    constant_time_eq(expected.as_bytes(), submitted.as_bytes())
}

/// Token acak base64url tanpa padding.
fn fresh_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("RNG sistem harus selalu tersedia");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Perbandingan byte constant-time untuk dua slice.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
