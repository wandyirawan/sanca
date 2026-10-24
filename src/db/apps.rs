//! Query dasar tabel `apps` dan `app_credentials`.
//!
//! Belum ada aturan bisnis di sini: hanya baca/tulis bertipe. Semua slug
//! diperlakukan sebagai teks biasa (kolomnya `text`, bukan `citext`).

use sqlx::PgPool;
use uuid::Uuid;

/// Jenis aplikasi, memetakan enum Postgres `app_kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "app_kind", rename_all = "lowercase")]
pub enum AppKind {
    Web,
    Spa,
    Service,
    Cli,
}

/// Satu baris app beserta setelan TTL dan daftar redirect yang diizinkan.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct App {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub kind: AppKind,
    pub is_active: bool,
    pub access_ttl_secs: i32,
    pub refresh_ttl_secs: i32,
    pub redirect_uris: Vec<String>,
}

/// Kredensial client untuk satu app. Hash secret tidak pernah keluar dari db layer
/// kecuali untuk dibandingkan di domain auth.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Credential {
    pub id: Uuid,
    pub app_id: Uuid,
    pub client_id: String,
    pub client_secret_hash: String,
}

/// Ambil satu app lewat slug (klaim `aud`).
pub async fn by_slug(pool: &PgPool, slug: &str) -> Result<Option<App>, sqlx::Error> {
    sqlx::query_as!(
        App,
        r#"
        SELECT id, slug, name, description, kind AS "kind: AppKind",
               is_active, access_ttl_secs, refresh_ttl_secs, redirect_uris
        FROM apps
        WHERE slug = $1
        "#,
        slug,
    )
    .fetch_optional(pool)
    .await
}

/// Ambil satu app lewat id.
pub async fn by_id(pool: &PgPool, id: Uuid) -> Result<Option<App>, sqlx::Error> {
    sqlx::query_as!(
        App,
        r#"
        SELECT id, slug, name, description, kind AS "kind: AppKind",
               is_active, access_ttl_secs, refresh_ttl_secs, redirect_uris
        FROM apps
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Daftar app dengan paging sederhana, terurut slug supaya stabil.
pub async fn list(pool: &PgPool, limit: i64, offset: i64) -> Result<Vec<App>, sqlx::Error> {
    sqlx::query_as!(
        App,
        r#"
        SELECT id, slug, name, description, kind AS "kind: AppKind",
               is_active, access_ttl_secs, refresh_ttl_secs, redirect_uris
        FROM apps
        ORDER BY slug
        LIMIT $1 OFFSET $2
        "#,
        limit,
        offset,
    )
    .fetch_all(pool)
    .await
}

/// Buat app baru. Kolom lain memakai default dari skema.
pub async fn insert(
    pool: &PgPool,
    slug: &str,
    name: &str,
    kind: AppKind,
) -> Result<App, sqlx::Error> {
    sqlx::query_as!(
        App,
        r#"
        INSERT INTO apps (id, slug, name, kind)
        VALUES ($1, $2, $3, $4)
        RETURNING id, slug, name, description, kind AS "kind: AppKind",
                  is_active, access_ttl_secs, refresh_ttl_secs, redirect_uris
        "#,
        Uuid::now_v7(),
        slug,
        name,
        kind as AppKind,
    )
    .fetch_one(pool)
    .await
}

/// Simpan kredensial client baru; mengembalikan id barisnya.
/// Secret yang masuk sudah berupa hash, bukan teks asli.
pub async fn create_credential(
    pool: &PgPool,
    app_id: Uuid,
    client_id: &str,
    client_secret_hash: &str,
) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        INSERT INTO app_credentials (id, app_id, client_id, client_secret_hash)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
        Uuid::now_v7(),
        app_id,
        client_id,
        client_secret_hash,
    )
    .fetch_one(pool)
    .await
}

/// Cari kredensial yang masih hidup (belum dicabut) lewat client_id.
pub async fn credential_by_client_id(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<Credential>, sqlx::Error> {
    sqlx::query_as!(
        Credential,
        r#"
        SELECT id, app_id, client_id, client_secret_hash
        FROM app_credentials
        WHERE client_id = $1
          AND revoked_at IS NULL
        "#,
        client_id,
    )
    .fetch_optional(pool)
    .await
}

/// Catat bahwa kredensial baru saja dipakai menerbitkan token.
///
/// Kegagalan di sini tidak boleh menggagalkan permintaan token, jadi pemanggil
/// yang memutuskan mau mengabaikan error-nya atau tidak.
pub async fn touch_credential(pool: &PgPool, credential_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE app_credentials
        SET last_used_at = now()
        WHERE id = $1
        "#,
        credential_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Cabut semua kredensial app yang masih hidup (rotate secret memakai ini).
pub async fn revoke_credentials(pool: &PgPool, app_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE app_credentials
        SET revoked_at = now()
        WHERE app_id = $1
          AND revoked_at IS NULL
        "#,
        app_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}
