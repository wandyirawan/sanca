//! Query dasar tabel `oauth_codes`.
//!
//! Tidak ada aturan bisnis di sini: hanya baca/tulis bertipe. Kode asli tidak
//! pernah masuk ke tabel ini — pemanggil wajib menyerahkan hash-nya.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Satu authorization code yang tersimpan, dalam bentuk hash.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OAuthCode {
    pub code_hash: String,
    pub app_id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub code_challenge: Option<String>,
    pub challenge_method: Option<String>,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
}

/// Satu kode yang akan disimpan. `code_hash` adalah SHA-256 hex dari nilai yang
/// dikirim ke client; kode aslinya tidak pernah sampai ke lapisan ini.
pub struct NewCode<'a> {
    pub code_hash: &'a str,
    pub app_id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub redirect_uri: &'a str,
    pub scope: &'a [String],
    pub code_challenge: Option<&'a str>,
    pub challenge_method: Option<&'a str>,
    pub expires_at: OffsetDateTime,
}

/// Simpan satu kode.
pub async fn insert(pool: &PgPool, code: &NewCode<'_>) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO oauth_codes (
            code_hash, app_id, user_id, session_id, redirect_uri, scope,
            code_challenge, challenge_method, expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
        code.code_hash,
        code.app_id,
        code.user_id,
        code.session_id,
        code.redirect_uri,
        code.scope,
        code.code_challenge,
        code.challenge_method,
        code.expires_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Cari kode yang masih boleh ditukar: belum kedaluwarsa dan belum dipakai.
pub async fn find_live_by_hash(
    pool: &PgPool,
    code_hash: &str,
) -> Result<Option<OAuthCode>, sqlx::Error> {
    sqlx::query_as!(
        OAuthCode,
        r#"
        SELECT code_hash, app_id, user_id, session_id, redirect_uri, scope,
               code_challenge, challenge_method, expires_at, consumed_at
        FROM oauth_codes
        WHERE code_hash = $1
          AND consumed_at IS NULL
          AND expires_at > now()
        "#,
        code_hash,
    )
    .fetch_optional(pool)
    .await
}

/// Tandai kode sudah dipakai, secara atomik.
///
/// `Some` hanya dikembalikan untuk pemanggil yang benar-benar berhasil mengubah
/// baris. Kalau dua request datang bersamaan dengan kode yang sama, hanya satu
/// yang mendapat `Some`; yang lain mendapat `None` dan harus ditolak.
pub async fn consume(pool: &PgPool, code_hash: &str) -> Result<Option<OAuthCode>, sqlx::Error> {
    sqlx::query_as!(
        OAuthCode,
        r#"
        UPDATE oauth_codes
        SET consumed_at = now()
        WHERE code_hash = $1
          AND consumed_at IS NULL
          AND expires_at > now()
        RETURNING code_hash, app_id, user_id, session_id, redirect_uri, scope,
                  code_challenge, challenge_method, expires_at, consumed_at
        "#,
        code_hash,
    )
    .fetch_optional(pool)
    .await
}
