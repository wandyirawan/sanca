//! Query dasar tabel `sessions`. Rotasi token dan aturan TTL ada di domain.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Satu sesi refresh. `refresh_hash` adalah hash dari token, bukan token aslinya.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub app_id: Uuid,
    pub refresh_hash: String,
    pub user_agent: String,
    pub expires_at: OffsetDateTime,
}

/// Catat sesi baru dan kembalikan id-nya (dipakai sebagai klaim `sid`).
/// Kolom `ip` bertipe `inet`, jadi teks dari header di-cast di SQL.
pub async fn insert(
    pool: &PgPool,
    user_id: Uuid,
    app_id: Uuid,
    refresh_hash: &str,
    expires_at: OffsetDateTime,
    user_agent: &str,
    ip: Option<&str>,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        INSERT INTO sessions (id, user_id, app_id, refresh_hash, expires_at, user_agent, ip)
        VALUES ($1, $2, $3, $4, $5, $6, $7::text::inet)
        RETURNING id
        "#,
        Uuid::now_v7(),
        user_id,
        app_id,
        refresh_hash,
        expires_at,
        user_agent,
        ip,
    )
    .fetch_one(pool)
    .await
}

/// Cari sesi hidup lewat hash refresh token.
pub async fn by_refresh_hash(pool: &PgPool, hash: &str) -> Result<Option<Session>, sqlx::Error> {
    sqlx::query_as!(
        Session,
        r#"
        SELECT id, user_id, app_id, refresh_hash, user_agent, expires_at
        FROM sessions
        WHERE refresh_hash = $1
          AND revoked_at IS NULL
        "#,
        hash,
    )
    .fetch_optional(pool)
    .await
}

/// Cabut satu sesi. Sesi yang sudah dicabut tidak diubah lagi.
pub async fn revoke(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE sessions
        SET revoked_at = now()
        WHERE id = $1
          AND revoked_at IS NULL
        "#,
        id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Cabut semua sesi hidup milik satu user di satu app (mis. setelah ganti password).
pub async fn revoke_all_for_user_app(
    pool: &PgPool,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE sessions
        SET revoked_at = now()
        WHERE user_id = $1
          AND app_id = $2
          AND revoked_at IS NULL
        "#,
        user_id,
        app_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}
