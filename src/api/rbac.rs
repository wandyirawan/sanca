//! Endpoint RBAC minimal: daftar role, buat role, dan katalog permission.
//!
//! Semua operasi terikat app `core`; app lain belum dilayani pada tahap ini.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;
use crate::state::AppState;

/// Batas panjang key dan nama role, cukup longgar untuk key bergaya `user_admin`.
const MAX_KEY: usize = 64;
const MAX_NAME: usize = 128;
const MAX_DESCRIPTION: usize = 512;

/// Router RBAC.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/roles", get(list_roles).post(create_role))
        .route("/api/permissions", get(list_permissions))
}

/// Ringkasan role untuk daftar di konsol.
#[derive(Debug, Serialize)]
pub struct RoleSummary {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub is_system: bool,
    /// Jumlah permission yang saat ini terpasang di role ini.
    pub permissions: i64,
}

/// Body pembuatan role. `description` opsional.
#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// Hasil pembuatan role.
#[derive(Debug, Serialize)]
pub struct CreatedRole {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub description: String,
    pub is_system: bool,
}

/// Satu baris katalog permission app core.
#[derive(Debug, Serialize)]
pub struct PermissionEntry {
    pub key: String,
    pub name: String,
    pub is_system: bool,
}

/// Daftar role app `core` beserta jumlah permission-nya.
async fn list_roles(State(state): State<AppState>) -> Result<Json<Vec<RoleSummary>>, AppError> {
    let roles = sqlx::query_as!(
        RoleSummary,
        r#"
        SELECT r.id, r.key, r.name, r.is_system,
               count(rp.permission_id) AS "permissions!"
        FROM roles r
        JOIN apps a ON a.id = r.app_id
        LEFT JOIN role_permissions rp ON rp.role_id = r.id
        WHERE a.slug = 'core'
        GROUP BY r.id
        ORDER BY r.key
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(roles))
}

/// Buat role baru di app `core`. Role buatan manusia selalu `is_system = false`.
async fn create_role(
    State(state): State<AppState>,
    Json(body): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<CreatedRole>), AppError> {
    let key = body.key.trim();
    let name = body.name.trim();

    if key.is_empty() || name.is_empty() {
        return Err(AppError::BadRequest(
            "key dan name role wajib diisi".to_string(),
        ));
    }

    if key.len() > MAX_KEY || name.len() > MAX_NAME || body.description.len() > MAX_DESCRIPTION {
        return Err(AppError::BadRequest(
            "key, name, atau description terlalu panjang".to_string(),
        ));
    }

    // ON CONFLICT ... DO NOTHING membuat key duplikat tidak menjadi error 500;
    // hasil kosong berarti role dengan key itu sudah ada.
    let created = sqlx::query_as!(
        CreatedRole,
        r#"
        INSERT INTO roles (id, app_id, key, name, description)
        SELECT $1, a.id, $2, $3, $4
        FROM apps a
        WHERE a.slug = 'core'
        ON CONFLICT (app_id, key) DO NOTHING
        RETURNING id, key, name, description, is_system
        "#,
        Uuid::now_v7(),
        key,
        name,
        body.description.trim(),
    )
    .fetch_optional(&state.pool)
    .await?;

    match created {
        Some(role) => Ok((StatusCode::CREATED, Json(role))),
        None => Err(AppError::BadRequest(
            "role dengan key itu sudah ada".to_string(),
        )),
    }
}

/// Katalog permission app `core`, terisi oleh sync registry saat boot.
async fn list_permissions(
    State(state): State<AppState>,
) -> Result<Json<Vec<PermissionEntry>>, AppError> {
    let permissions = sqlx::query_as!(
        PermissionEntry,
        r#"
        SELECT p.key, p.name, p.is_system
        FROM permissions p
        JOIN apps a ON a.id = p.app_id
        WHERE a.slug = 'core'
        ORDER BY p.key
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(permissions))
}
