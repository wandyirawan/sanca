//! Query tabel `audit_events`: satu insert append-only dan satu list dengan filter.
//!
//! Tidak ada update/delete di sini — jejak audit tidak boleh diubah dari aplikasi.

use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Siapa pelaku sebuah event, memetakan enum Postgres `actor_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "actor_type", rename_all = "lowercase")]
pub enum ActorType {
    User,
    Service,
    System,
}

/// Bahan satu event baru. Slug app disimpan sebagai teks supaya jejak tetap
/// terbaca walau app-nya kelak dihapus.
#[derive(Debug, Clone)]
pub struct NewEvent<'a> {
    pub app_id: Option<Uuid>,
    pub app_slug: &'a str,
    pub actor_type: ActorType,
    pub actor_user_id: Option<Uuid>,
    pub action: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub status_code: Option<i16>,
    pub request_id: &'a str,
    pub metadata: Value,
}

/// Satu baris audit yang siap ditampilkan di API/console.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditRow {
    pub id: i64,
    pub occurred_at: OffsetDateTime,
    pub app_slug: String,
    pub actor_type: ActorType,
    pub actor_user_id: Option<Uuid>,
    pub action: String,
    pub method: String,
    pub path: String,
    pub status_code: Option<i32>,
    pub request_id: String,
}

/// Tulis satu event, kembalikan id bigserial-nya.
pub async fn insert(pool: &PgPool, ev: &NewEvent<'_>) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        INSERT INTO audit_events
            (app_id, app_slug, actor_type, actor_user_id, action,
             method, path, status_code, request_id, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8::int2, $9, $10)
        RETURNING id
        "#,
        ev.app_id,
        ev.app_slug,
        ev.actor_type as ActorType,
        ev.actor_user_id,
        ev.action,
        ev.method,
        ev.path,
        ev.status_code,
        ev.request_id,
        ev.metadata,
    )
    .fetch_one(pool)
    .await
}

/// Daftar event terbaru. Filter app dan pelaku bersifat opsional: `None` berarti
/// semua app / semua pelaku, jadi satu fungsi cukup untuk kedua kebutuhan itu.
pub async fn list(
    pool: &PgPool,
    app_slug: Option<&str>,
    actor_user_id: Option<Uuid>,
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    sqlx::query_as!(
        AuditRow,
        r#"
        SELECT id,
               occurred_at,
               app_slug,
               actor_type AS "actor_type: ActorType",
               actor_user_id AS "actor_user_id?",
               action,
               method,
               path,
               status_code AS "status_code?",
               request_id
        FROM audit_events
        WHERE ($1::text IS NULL OR app_slug = $1)
          AND ($2::uuid IS NULL OR actor_user_id = $2)
        ORDER BY occurred_at DESC, id DESC
        LIMIT $3 OFFSET $4
        "#,
        app_slug,
        actor_user_id,
        limit,
        offset,
    )
    .fetch_all(pool)
    .await
}
