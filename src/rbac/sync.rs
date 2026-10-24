//! Sinkronisasi registry ke tabel `permissions` app `core`.
//!
//! Dijalankan saat boot dan idempoten: permission yang sudah ada dibiarkan,
//! yang belum ada disisipkan. Nama permission sama dengan key-nya karena pada
//! tahap ini belum ada tabel nama terpisah.

use sqlx::PgPool;
use uuid::Uuid;

use crate::rbac::registry;

/// Pastikan setiap permission di registry punya baris di app `core`.
///
/// Mengembalikan jumlah baris yang benar-benar baru disisipkan.
pub async fn sync(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let mut inserted = 0u64;

    for key in registry::permissions() {
        let result = sqlx::query!(
            r#"
            INSERT INTO permissions (id, app_id, key, name, is_system)
            SELECT $1, a.id, $2, $2, true
            FROM apps a
            WHERE a.slug = 'core'
            ON CONFLICT DO NOTHING
            "#,
            Uuid::now_v7(),
            key,
        )
        .execute(pool)
        .await?;

        inserted += result.rows_affected();
    }

    tracing::info!(jumlah_baru = inserted, "sync permission registry selesai");
    Ok(inserted)
}
