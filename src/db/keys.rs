//! Query tabel `signing_keys`. DB hanya menyimpan public key; private key
//! hidup di env/file, jadi modul ini tidak pernah menyentuhnya.

use sqlx::PgPool;

/// Satu public key yang bisa dipublikasikan lewat JWKS.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SigningKey {
    pub kid: String,
    pub alg: String,
    pub public_pem: String,
}

/// Simpan public key baru.
pub async fn insert(pool: &PgPool, kid: &str, public_pem: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO signing_keys (kid, public_pem)
        VALUES ($1, $2)
        "#,
        kid,
        public_pem,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Daftarkan public key kalau `kid` belum punya baris sama sekali.
///
/// `ON CONFLICT DO NOTHING` penting: kunci yang sudah dipensiunkan punya baris,
/// jadi file yang sengaja dibiarkan di disk tidak akan pernah menghidupkannya
/// kembali. Dipakai startup untuk memastikan setiap kunci punya baris DB.
pub async fn backfill(pool: &PgPool, kid: &str, public_pem: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO signing_keys (kid, public_pem)
        VALUES ($1, $2)
        ON CONFLICT (kid) DO NOTHING
        "#,
        kid,
        public_pem,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Semua key yang belum dipensiunkan, terbaru dulu.
pub async fn list_active(pool: &PgPool) -> Result<Vec<SigningKey>, sqlx::Error> {
    sqlx::query_as!(
        SigningKey,
        r#"
        SELECT kid, alg, public_pem
        FROM signing_keys
        WHERE retired_at IS NULL
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await
}

/// `kid` yang sudah dipensiunkan, supaya filenya yang masih ada di disk tidak
/// dianggap hidup lagi.
pub async fn list_retired(pool: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT kid
        FROM signing_keys
        WHERE retired_at IS NOT NULL
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|row| row.kid).collect())
}

/// Tandai satu baris sebagai satu-satunya kunci aktif.
///
/// Kolom `is_active` hanya cermin untuk operator; sumber kebenaran urutan
/// kunci tetap `created_at` + `retired_at`. Menjaganya akurat membuat
/// `select * from signing_keys` tidak menyesatkan.
pub async fn mark_active(pool: &PgPool, kid: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE signing_keys
        SET is_active = (kid = $1)
        WHERE retired_at IS NULL
        "#,
        kid,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Apakah `kid` punya baris di `signing_keys`, apa pun statusnya.
pub async fn exists(pool: &PgPool, kid: &str) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT EXISTS (SELECT 1 FROM signing_keys WHERE kid = $1) AS "ada!"
        "#,
        kid,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.ada)
}

/// Pensiunkan satu key: tidak lagi ditandai aktif dan diberi waktu retire.
///
/// Mengembalikan jumlah baris yang benar-benar berubah, supaya CLI bisa
/// membedakan "kid tidak ada" dari "kid sudah pensiun".
pub async fn retire(pool: &PgPool, kid: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        UPDATE signing_keys
        SET is_active = false,
            retired_at = now()
        WHERE kid = $1
          AND retired_at IS NULL
        "#,
        kid,
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}
