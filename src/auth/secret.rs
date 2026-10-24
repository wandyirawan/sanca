//! Pembuatan dan verifikasi secret client untuk kredensial mesin-ke-mesin.
//!
//! Secret disimpan sebagai `SHA-256(pepper ‖ secret)` dalam bentuk hex. Secret
//! aslinya acak 256 bit, jadi hash cepat sudah cukup: tidak ada ruang tebak yang
//! bisa dimanfaatkan penyerang walau tabel `app_credentials` bocor. Pepper
//! dipisah dari database supaya bocornya dump saja tidak cukup untuk menguji
//! tebakan secret secara offline.

use std::fmt;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rand::TryRngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Panjang secret mentah sebelum di-encode, dalam byte.
const SECRET_BYTES: usize = 32;

/// Kegagalan pada operasi secret client.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretError {
    /// Secret atau pepper kosong; tidak ada yang bisa di-hash.
    Empty,
    /// Pepper tidak bisa di-decode dari base64.
    PepperUnavailable,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::Empty => f.write_str("secret client tidak boleh kosong"),
            SecretError::PepperUnavailable => f.write_str("pepper client tidak bisa dibaca"),
        }
    }
}

impl std::error::Error for SecretError {}

/// Buat secret client baru: 32 byte acak dari RNG sistem, base64url tanpa padding.
///
/// Tanpa padding supaya aman dipakai di header HTTP dan tidak perlu di-escape
/// saat ditempel ke file konfigurasi.
pub fn generate_client_secret() -> String {
    let mut bytes = [0u8; SECRET_BYTES];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("RNG sistem harus selalu tersedia");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash secret menjadi hex SHA-256 dari `pepper ‖ secret`.
pub fn hash_client_secret(secret: &str, pepper: &SecretString) -> Result<String, SecretError> {
    if secret.is_empty() {
        return Err(SecretError::Empty);
    }

    let pepper = decode_pepper(pepper)?;

    let mut hasher = Sha256::new();
    hasher.update(pepper.as_slice());
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();

    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

/// Bandingkan secret dengan hash tersimpan memakai perbandingan constant-time.
///
/// Secret kosong selalu ditolak lebih dulu, dan hash tersimpan yang bukan hex
/// 64 karakter juga ditolak tanpa pernah menyentuh database lagi.
pub fn verify_client_secret(
    secret: &str,
    stored_hash: &str,
    pepper: &SecretString,
) -> Result<bool, SecretError> {
    if secret.is_empty() {
        return Ok(false);
    }

    let computed = hash_client_secret(secret, pepper)?;
    Ok(constant_time_eq(
        computed.as_bytes(),
        stored_hash.as_bytes(),
    ))
}

/// Perbandingan byte demi byte yang tidak berhenti di byte pertama yang beda.
///
/// Panjang yang berbeda tetap dilaporkan `false`; panjang hash kita selalu 64
/// karakter sehingga kebocoran panjang tidak berarti apa-apa di sini.
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

/// Decode pepper base64 menjadi byte mentah; buffer dinolkan saat di-drop.
fn decode_pepper(pepper: &SecretString) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    STANDARD
        .decode(pepper.expose_secret().as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| SecretError::PepperUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pepper() -> SecretString {
        SecretString::from(STANDARD.encode(b"pepper-uji-32-byte-panjangnya!!!!"))
    }

    #[test]
    fn hash_stabil_dan_verifikasi_cocok() {
        let secret = generate_client_secret();
        let hash = hash_client_secret(&secret, &pepper()).unwrap();

        assert_eq!(hash.len(), 64);
        assert!(verify_client_secret(&secret, &hash, &pepper()).unwrap());
    }

    #[test]
    fn secret_salah_dan_kosong_ditolak() {
        let secret = generate_client_secret();
        let hash = hash_client_secret(&secret, &pepper()).unwrap();

        assert!(!verify_client_secret("secret-lain", &hash, &pepper()).unwrap());
        assert!(!verify_client_secret("", &hash, &pepper()).unwrap());
        assert_eq!(
            hash_client_secret("", &pepper()).unwrap_err(),
            SecretError::Empty
        );
    }

    #[test]
    fn secret_berbeda_setiap_pemanggilan() {
        assert_ne!(generate_client_secret(), generate_client_secret());
    }
}
