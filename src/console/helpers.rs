//! Fungsi kecil yang dipakai view dan handler console.
//!
//! Tidak ada abstraksi di sini: semuanya fungsi bebas, supaya template cukup
//! memanggil satu nama dan handler tidak menyimpan aturan tersembunyi.

use sha2::{Digest, Sha256};

/// Nama role yang melewati semua pemeriksaan permission.
pub const SUPERADMIN: &str = "superadmin";

/// Apakah pemilik sesi boleh melihat sesuatu yang butuh `permission`.
///
/// Aturannya sama dengan `rbac::enforce`: superadmin lolos tanpa melihat scope,
/// selain itu permission harus benar-benar ada di klaim `scope` token. Ini hanya
/// menyembunyikan menu; penegakan sebenarnya tetap di registry route.
pub fn can(scope: &[String], roles: &[String], permission: &str) -> bool {
    roles.iter().any(|role| role == SUPERADMIN) || scope.iter().any(|item| item == permission)
}

/// Ambil satu nilai cookie dari header `Cookie` mentah.
///
/// Dipakai middleware sesi yang berjalan sebelum ekstraktor `CookieJar`
/// (middleware tidak punya akses ke `Parts`).
pub fn cookie_value<'a>(cookie_header: Option<&'a str>, name: &str) -> Option<&'a str> {
    cookie_header?.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key.trim() == name).then(|| value.trim())
    })
}

/// SHA-256 hex dari refresh token.
///
/// Salinan kecil dari jalur API: `api/auth.rs` tidak boleh diubah di phase ini,
/// dan fungsinya privat di sana. Yang diduplikasi hanya bentuk hash, bukan
/// aturan verifikasi kredensial.
pub fn hash_refresh_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}
