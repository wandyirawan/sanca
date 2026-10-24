//! Query dasar tabel `users`. Otorisasi, sesi, dan audit belum ada di phase ini.

use sqlx::PgPool;
use uuid::Uuid;

/// Status akun, memetakan enum Postgres `user_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "user_status", rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Disabled,
    Pending,
}

/// Kolom user yang aman dibaca berulang. Password hanya pernah berupa hash.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub status: UserStatus,
    pub is_superadmin: bool,
    pub token_version: i32,
}

/// Simpan user baru. Id dibuat di aplikasi sebagai UUID v7 supaya urut waktu.
pub async fn insert(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
    display_name: &str,
) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (id, email, password_hash, display_name)
        VALUES ($1, $2, $3, $4)
        RETURNING id, email::text AS "email!", password_hash,
                  status AS "status: UserStatus", is_superadmin, token_version
        "#,
        Uuid::now_v7(),
        email,
        password_hash,
        display_name,
    )
    .fetch_one(pool)
    .await
}

/// Cari user lewat email. Kolomnya `citext`, jadi perbandingan tidak peduli kapital.
pub async fn by_email(pool: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
        SELECT id, email::text AS "email!", password_hash,
               status AS "status: UserStatus", is_superadmin, token_version
        FROM users
        WHERE email = $1::citext
        "#,
        email,
    )
    .fetch_optional(pool)
    .await
}
