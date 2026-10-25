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
    description: &str,
) -> Result<App, sqlx::Error> {
    sqlx::query_as!(
        App,
        r#"
        INSERT INTO apps (id, slug, name, kind, description)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, slug, name, description, kind AS "kind: AppKind",
                  is_active, access_ttl_secs, refresh_ttl_secs, redirect_uris
        "#,
        Uuid::now_v7(),
        slug,
        name,
        kind as AppKind,
        description,
    )
    .fetch_one(pool)
    .await
}

/// Satu baris daftar app: kolom tabel ditambah jumlah kredensial yang masih hidup.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AppRow {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub kind: AppKind,
    pub is_active: bool,
    pub access_ttl_secs: i32,
    pub live_credentials: i64,
}

/// Jumlah app yang tampil di satu halaman konsol.
///
/// Katalog app jauh lebih kecil daripada katalog user (biasanya belasan baris),
/// jadi layar ini tidak memakai pager: satu permintaan mengambil semuanya.
const LIST_LIMIT: i64 = 200;

/// Daftar app terurut slug, dengan filter opsional pada slug/nama.
///
/// `filter` kosong atau berisi spasi saja dianggap "tanpa filter", bukan pola
/// `%%` yang tetap memaksa pemindaian tabel.
pub async fn list_rows(pool: &PgPool, filter: Option<&str>) -> Result<Vec<AppRow>, sqlx::Error> {
    let pattern = filter
        .map(str::trim)
        .filter(|q| !q.is_empty())
        .map(|q| format!("%{q}%"));

    sqlx::query_as!(
        AppRow,
        r#"
        SELECT a.id, a.slug, a.name, a.kind AS "kind: AppKind", a.is_active,
               a.access_ttl_secs,
               (SELECT count(*) FROM app_credentials c
                WHERE c.app_id = a.id AND c.revoked_at IS NULL) AS "live_credentials!"
        FROM apps a
        WHERE ($1::text IS NULL OR a.slug ILIKE $1 OR a.name ILIKE $1)
        ORDER BY a.slug
        LIMIT $2
        "#,
        pattern.as_deref(),
        LIST_LIMIT,
    )
    .fetch_all(pool)
    .await
}

/// Jumlah seluruh app; dipakai membedakan "katalog kosong" dari "filter kosong".
pub async fn count(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(r#"SELECT count(*) AS "count!" FROM apps"#)
        .fetch_one(pool)
        .await
}

/// Hapus app beserta kredensialnya. Hanya dipakai saat pembuatan gagal di
/// tengah jalan supaya tidak ada app setengah jadi tanpa kredensial.
pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(r#"DELETE FROM apps WHERE id = $1"#, id)
        .execute(pool)
        .await?;
    Ok(())
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
