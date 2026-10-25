//! Query dasar tabel `users`. Otorisasi, sesi, dan audit belum ada di phase ini.

use sqlx::PgPool;
use time::OffsetDateTime;
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

/// Baris user untuk kebutuhan konsol: semua kolom yang boleh dilihat klien,
/// tanpa `password_hash` dan `pepper_version`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserDetail {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub status: UserStatus,
    pub is_superadmin: bool,
    pub token_version: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Simpan user baru dengan default aman: bukan superadmin, pepper versi 1.
pub async fn insert(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
    display_name: &str,
) -> Result<User, sqlx::Error> {
    insert_with_flags(
        pool,
        email,
        password_hash,
        display_name,
        false,
        crate::config::DEFAULT_PEPPER_VERSION,
    )
    .await
}

/// Simpan user baru sekaligus menentukan status superadmin dan versi pepper.
///
/// Dipakai subcommand `sanca user create`; parameter eksplisit supaya jalur
/// pembuatan admin tidak perlu UPDATE susulan yang bisa lupa dijalankan.
pub async fn insert_with_flags<'e, E>(
    executor: E,
    email: &str,
    password_hash: &str,
    display_name: &str,
    is_superadmin: bool,
    pepper_version: i16,
) -> Result<User, sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (id, email, password_hash, pepper_version, display_name, is_superadmin)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, email::text AS "email!", password_hash,
                  status AS "status: UserStatus", is_superadmin, token_version
        "#,
        Uuid::now_v7(),
        email,
        password_hash,
        pepper_version,
        display_name,
        is_superadmin,
    )
    .fetch_one(executor)
    .await
}

/// Cari user lewat id. Dipakai jalur refresh, yang hanya memegang `user_id`
/// dari baris sesi.
pub async fn by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(
        User,
        r#"
        SELECT id, email::text AS "email!", password_hash,
               status AS "status: UserStatus", is_superadmin, token_version
        FROM users
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
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

/// Satu baris user versi konsol, atau `None` kalau id tidak ada.
pub async fn detail(pool: &PgPool, id: Uuid) -> Result<Option<UserDetail>, sqlx::Error> {
    sqlx::query_as!(
        UserDetail,
        r#"
        SELECT id, email::text AS "email!", display_name,
               status AS "status: UserStatus", is_superadmin, token_version,
               created_at, updated_at
        FROM users
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Daftar user terurut email, dengan filter bebas pada email atau display_name.
///
/// `q` kosong atau berisi spasi saja diperlakukan sebagai tanpa filter, supaya
/// klien tidak perlu tahu aturan itu.
pub async fn list(
    pool: &PgPool,
    q: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<UserDetail>, sqlx::Error> {
    let pattern = q
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(|text| format!("%{text}%"));

    sqlx::query_as!(
        UserDetail,
        r#"
        SELECT id, email::text AS "email!", display_name,
               status AS "status: UserStatus", is_superadmin, token_version,
               created_at, updated_at
        FROM users
        WHERE $1::text IS NULL
           OR email::text ILIKE $1
           OR display_name ILIKE $1
        ORDER BY email
        LIMIT $2 OFFSET $3
        "#,
        pattern,
        limit,
        offset,
    )
    .fetch_all(pool)
    .await
}

/// Ubah profil dan/atau status. Kolom yang `None` dibiarkan apa adanya.
///
/// Fungsi ini sengaja tidak menyentuh `token_version`: kenaikan versi adalah
/// keputusan bisnis, jadi diputuskan di lapisan domain.
pub async fn update_profile(
    pool: &PgPool,
    id: Uuid,
    display_name: Option<&str>,
    status: Option<UserStatus>,
) -> Result<Option<UserDetail>, sqlx::Error> {
    sqlx::query_as!(
        UserDetail,
        r#"
        UPDATE users
        SET display_name = COALESCE($2, display_name),
            status = COALESCE($3::user_status, status),
            updated_at = now()
        WHERE id = $1
        RETURNING id, email::text AS "email!", display_name,
                  status AS "status: UserStatus", is_superadmin, token_version,
                  created_at, updated_at
        "#,
        id,
        display_name,
        status as Option<UserStatus>,
    )
    .fetch_optional(pool)
    .await
}

/// Ganti hash password sekaligus menaikkan `token_version`, sehingga seluruh
/// token lama langsung ditolak. Mengembalikan versi baru, atau `None` kalau
/// user tidak ada.
pub async fn set_password(
    pool: &PgPool,
    id: Uuid,
    password_hash: &str,
) -> Result<Option<i32>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        UPDATE users
        SET password_hash = $2,
            token_version = token_version + 1,
            updated_at = now()
        WHERE id = $1
        RETURNING token_version
        "#,
        id,
        password_hash,
    )
    .fetch_optional(pool)
    .await
}

/// Nonaktifkan akun dan cabut semua tokennya dalam satu langkah.
pub async fn disable(pool: &PgPool, id: Uuid) -> Result<Option<i32>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        UPDATE users
        SET status = 'disabled',
            token_version = token_version + 1,
            updated_at = now()
        WHERE id = $1
        RETURNING token_version
        "#,
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Baris user untuk tabel konsol: kolom aman ditambah jumlah role.
///
/// `role_count` dihitung di SQL, bukan di loop handler, supaya satu halaman
/// daftar tidak memicu satu query tambahan per baris.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub status: UserStatus,
    pub is_superadmin: bool,
    pub role_count: i64,
}

/// Daftar user versi tabel konsol, terurut email, lengkap dengan jumlah role.
///
/// Aturan pencariannya sama dengan `list`: `q` kosong atau berisi spasi saja
/// berarti tanpa filter, dan pencocokan memakai `ILIKE` pada email/nama.
pub async fn list_rows(
    pool: &PgPool,
    q: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<UserRow>, sqlx::Error> {
    let pattern = q
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(|text| format!("%{text}%"));

    sqlx::query_as!(
        UserRow,
        r#"
        SELECT u.id, u.email::text AS "email!", u.display_name,
               u.status AS "status: UserStatus", u.is_superadmin,
               (SELECT count(*) FROM user_roles ur WHERE ur.user_id = u.id)
                   AS "role_count!"
        FROM users u
        WHERE $1::text IS NULL
           OR u.email::text ILIKE $1
           OR u.display_name ILIKE $1
        ORDER BY u.email
        LIMIT $2 OFFSET $3
        "#,
        pattern,
        limit,
        offset,
    )
    .fetch_all(pool)
    .await
}

/// Jumlah user yang cocok dengan filter yang sama seperti `list_rows`.
///
/// Dipisah supaya pager bisa menulis "1-20 dari 57" tanpa mengambil semua baris.
pub async fn count(pool: &PgPool, q: Option<&str>) -> Result<i64, sqlx::Error> {
    let pattern = q
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(|text| format!("%{text}%"));

    sqlx::query_scalar!(
        r#"
        SELECT count(*) AS "total!"
        FROM users u
        WHERE $1::text IS NULL
           OR u.email::text ILIKE $1
           OR u.display_name ILIKE $1
        "#,
        pattern,
    )
    .fetch_one(pool)
    .await
}

/// Naikkan `token_version` tanpa mengubah kolom lain; dipakai saat akun
/// diaktifkan kembali atau status berubah ke nilai selain `disabled`.
pub async fn bump_token_version(pool: &PgPool, id: Uuid) -> Result<Option<i32>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        UPDATE users
        SET token_version = token_version + 1,
            updated_at = now()
        WHERE id = $1
        RETURNING token_version
        "#,
        id,
    )
    .fetch_optional(pool)
    .await
}
