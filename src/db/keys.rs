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

/// Pensiunkan satu key: tidak lagi ditandai aktif dan diberi waktu retire.
pub async fn retire(pool: &PgPool, kid: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
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
    Ok(())
}
