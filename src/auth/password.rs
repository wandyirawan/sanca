//! Hash dan verifikasi password dengan Argon2id.
//!
//! Parameter (m=19456 KiB, t=2, p=1) mengikuti rekomendasi OWASP dan §7 AGENTS.
//! Pepper disuntik sebagai `secret` Argon2, bukan ditempel ke password, jadi
//! bocornya tabel `users` saja tidak cukup untuk memulai cracking offline.

use std::fmt;

use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::TryRngCore;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// Panjang minimum password yang diterima, dalam karakter.
pub const MIN_PASSWORD_LEN: usize = 12;

/// Biaya memori Argon2id dalam KiB (19 MiB).
const MEMORY_KIB: u32 = 19_456;
/// Jumlah iterasi.
const TIME_COST: u32 = 2;
/// Paralelisme.
const PARALLELISM: u32 = 1;
/// Panjang salt, dibaca dari sistem RNG.
const SALT_LEN: usize = 16;

/// Kegagalan pada operasi password.
#[derive(Debug)]
pub enum PasswordError {
    /// Password lebih pendek dari [`MIN_PASSWORD_LEN`].
    TooShort,
    /// Pepper tidak bisa di-decode dari base64.
    PepperUnavailable,
    /// `pepper_version` yang diminta bukan versi yang dikenal proses ini.
    UnsupportedPepperVersion(i16),
    /// Hash PHC tersimpan rusak atau tidak bisa diproses.
    InvalidHash,
    /// Kebijakan password kita sendiri menolak input (misalnya terlalu panjang).
    Rejected,
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasswordError::TooShort => write!(f, "password minimal {MIN_PASSWORD_LEN} karakter"),
            PasswordError::PepperUnavailable => write!(f, "pepper tidak bisa dibaca"),
            PasswordError::UnsupportedPepperVersion(v) => {
                write!(f, "versi pepper {v} tidak dikenal proses ini")
            }
            PasswordError::InvalidHash => write!(f, "hash password tidak valid"),
            PasswordError::Rejected => write!(f, "password ditolak kebijakan"),
        }
    }
}

impl std::error::Error for PasswordError {}

/// Hash password polos menjadi PHC string (`$argon2id$v=19$m=...`).
pub fn hash_password(plain: &str, pepper: &SecretString) -> Result<String, PasswordError> {
    if plain.chars().count() < MIN_PASSWORD_LEN {
        return Err(PasswordError::TooShort);
    }

    let secret = decode_pepper(pepper)?;
    let argon2 = argon2_with_secret(&secret)?;

    // Salt selalu dari OsRng sistem, bukan PRNG yang bisa di-seed.
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| PasswordError::PepperUnavailable)?;

    let hash = argon2
        .hash_password_with_salt(plain.as_bytes(), &salt)
        .map_err(|_| PasswordError::Rejected)?;

    Ok(hash.to_string())
}

/// Verifikasi password terhadap PHC string tersimpan.
///
/// `pepper_version` adalah nilai di kolom `users.pepper_version`; hanya versi
/// yang didukung proses ini yang diterima, sisanya ditolak supaya rotasi pepper
/// tidak diam-diam memverifikasi dengan kunci yang salah.
pub fn verify_password(
    plain: &str,
    phc: &str,
    pepper_version: i16,
    pepper: &SecretString,
) -> Result<bool, PasswordError> {
    if pepper_version != crate::config::DEFAULT_PEPPER_VERSION {
        return Err(PasswordError::UnsupportedPepperVersion(pepper_version));
    }

    let secret = decode_pepper(pepper)?;
    let argon2 = argon2_with_secret(&secret)?;

    match argon2.verify_password(plain.as_bytes(), phc) {
        Ok(()) => Ok(true),
        // Password salah bukan error: pemanggil butuh bedanya dengan hash rusak.
        Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
        Err(_) => Err(PasswordError::InvalidHash),
    }
}

/// Decode pepper base64 menjadi byte mentah; buffer dinolkan saat di-drop.
fn decode_pepper(pepper: &SecretString) -> Result<Zeroizing<Vec<u8>>, PasswordError> {
    STANDARD
        .decode(pepper.expose_secret().as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| PasswordError::PepperUnavailable)
}

/// Bangun instance Argon2id dengan parameter tetap, meminjam pepper yang sudah
/// di-decode supaya tidak ada salinan secret yang hidup lebih lama dari perlu.
fn argon2_with_secret<'a>(secret: &'a [u8]) -> Result<Argon2<'a>, PasswordError> {
    let params = Params::new(MEMORY_KIB, TIME_COST, PARALLELISM, None)
        .map_err(|_| PasswordError::Rejected)?;

    Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
        .map_err(|_| PasswordError::PepperUnavailable)
}
