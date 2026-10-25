//! Aturan bisnis seputar aplikasi: bentuk slug yang sah, kapan kredensial
//! dicabut, dan urutan langkah saat app dibuat atau secret dirotasi.
//!
//! Satu-satunya tempat yang menghasilkan `client_secret` mentah. Nilai itu
//! dikembalikan ke pemanggil (CLI atau handler console) untuk ditampilkan sekali,
//! lalu hilang: yang tersimpan di database hanya hash-nya. `api/` dan `console/`
//! sama-sama memanggil fungsi di sini, jadi tidak ada dua implementasi rotasi
//! yang bisa menyimpang.
//!
//! Fungsi di sini menerima `&PgPool` + `&Config`, bukan `&AppState`: perintah CLI
//! tidak punya signing key dan tidak seharusnya membuatnya hanya untuk menyentuh
//! tabel apps.

use rand::TryRngCore;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::secret::{generate_client_secret, hash_client_secret};
use crate::config::Config;
use crate::db::apps::{self, App, AppKind};
use crate::error::AppError;

/// Slug app `core` tidak boleh dibuat ulang: console dan migrasi bergantung
/// pada satu baris itu, dan slug-nya adalah klaim `aud` semua token console.
const RESERVED_SLUG: &str = "core";

/// Batas panjang slug. Cukup untuk nama service yang deskriptif, masih aman
/// dipakai di header dan URL.
const MAX_SLUG_LEN: usize = 63;

/// Kredensial yang baru diterbitkan. `client_secret` hanya hidup di memori
/// pemanggil dan di respons HTTP yang menampilkannya sekali.
pub struct IssuedCredential {
    pub client_id: String,
    pub client_secret: String,
}

/// Periksa bentuk slug dan kembalikan versi yang sudah dinormalisasi.
///
/// Aturannya sengaja sempit: huruf kecil, angka, dan tanda hubung, tidak diawali
/// atau diakhiri tanda hubung, maksimal 63 karakter, dan bukan `core`. Slug
/// menjadi klaim `aud` sekaligus `azp`, jadi bentuk yang aneh di sini akan
/// merepotkan semua downstream.
pub fn validate_slug(raw: &str) -> Result<String, AppError> {
    let slug = raw.trim();

    if slug.is_empty() {
        return Err(AppError::BadRequest(
            "slug aplikasi wajib diisi".to_string(),
        ));
    }

    if slug.len() > MAX_SLUG_LEN {
        return Err(AppError::BadRequest(format!(
            "slug aplikasi maksimal {MAX_SLUG_LEN} karakter"
        )));
    }

    if slug == RESERVED_SLUG {
        return Err(AppError::BadRequest(
            "slug core dipakai console dan tidak bisa dibuat ulang".to_string(),
        ));
    }

    let sah = slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !slug.starts_with('-')
        && !slug.ends_with('-');

    if !sah {
        return Err(AppError::BadRequest(
            "slug hanya boleh huruf kecil, angka, dan tanda hubung, tanpa tanda hubung \
             di awal atau akhir"
                .to_string(),
        ));
    }

    Ok(slug.to_string())
}

/// Buat app baru sekaligus kredensial client pertamanya.
///
/// Kalau penerbitan kredensial gagal, app yang terlanjur tersimpan dihapus
/// kembali: app tanpa kredensial tidak bisa dipakai apa pun dan hanya
/// mengotori daftar.
pub async fn create_app(
    pool: &PgPool,
    config: &Config,
    slug: &str,
    name: &str,
    kind: AppKind,
    description: &str,
) -> Result<(App, IssuedCredential), AppError> {
    let slug = validate_slug(slug)?;

    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest(
            "nama aplikasi wajib diisi".to_string(),
        ));
    }

    if apps::by_slug(pool, &slug).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "slug {slug} sudah dipakai aplikasi lain"
        )));
    }

    let app = apps::insert(pool, &slug, name, kind, description.trim())
        .await
        .map_err(insert_error)?;

    match issue_credential(pool, config, app.id, &slug).await {
        Ok(credential) => Ok((app, credential)),
        Err(err) => {
            if let Err(cleanup) = apps::delete(pool, app.id).await {
                tracing::error!(error = %cleanup, "gagal menghapus app tanpa kredensial");
            }
            Err(err)
        }
    }
}

/// Rotasi secret satu app: cabut semua kredensial hidup dulu, baru terbitkan
/// pasangan baru.
///
/// Urutannya penting. Kalau penerbitan gagal setelah pencabutan, app berhenti
/// bisa meminta token — itu kegagalan yang terlihat, bukan dua secret hidup
/// yang diam-diam berlaku bersamaan.
pub async fn rotate_secret(
    pool: &PgPool,
    config: &Config,
    app_id: Uuid,
) -> Result<IssuedCredential, AppError> {
    let app = apps::by_id(pool, app_id).await?.ok_or(AppError::NotFound)?;

    apps::revoke_credentials(pool, app.id).await?;

    issue_credential(pool, config, app.id, &app.slug).await
}

/// Terbitkan client_id + secret baru dan simpan hash-nya.
async fn issue_credential(
    pool: &PgPool,
    config: &Config,
    app_id: Uuid,
    slug: &str,
) -> Result<IssuedCredential, AppError> {
    let client_id = new_client_id(slug);
    let client_secret = generate_client_secret();

    let hash = hash_client_secret(&client_secret, &config.client_secret_pepper).map_err(|err| {
        tracing::error!(error = %err, "secret client ditolak saat hashing");
        AppError::Internal
    })?;

    apps::create_credential(pool, app_id, &client_id, &hash).await?;

    Ok(IssuedCredential {
        client_id,
        client_secret,
    })
}

/// `client_id` tidak rahasia, jadi cukup mudah dibaca: slug plus 12 karakter
/// acak hex supaya dua app dengan slug mirip tidak pernah bertabrakan.
fn new_client_id(slug: &str) -> String {
    let mut bytes = [0u8; 6];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("RNG sistem harus selalu tersedia");

    let suffix: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{slug}-{suffix}")
}

/// Pelanggaran unique pada slug (dua permintaan bersamaan) tetap dilaporkan
/// sebagai konflik, bukan 500.
fn insert_error(err: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db) = &err
        && db.code().as_deref() == Some("23505")
    {
        return AppError::Conflict("slug itu sudah dipakai aplikasi lain".to_string());
    }

    tracing::error!(error = %err, "gagal menyimpan app");
    AppError::Internal
}
