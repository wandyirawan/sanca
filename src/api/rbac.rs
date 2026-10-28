//! Endpoint RBAC: daftar role, buat role, katalog permission, isi permission
//! sebuah role, dan hapus role.
//!
//! Semua operasi terikat app `core`; app lain belum dilayani pada tahap ini.
//! Handler di sini hanya urusan bentuk request dan bentuk respons. Keputusan
//! boleh/tidak ada di `domain::rbac`, dan SQL-nya di `db::rbac`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::extractor::AuthUser;
use crate::db::rbac;
use crate::domain::rbac as domain_rbac;
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
        .route(
            "/api/roles/{id}/permissions",
            get(get_role_permissions).put(set_role_permissions),
        )
        .route("/api/roles/{id}", delete(remove_role))
}

/// Ringkasan role untuk daftar di konsol.
#[derive(Debug, Serialize, ToSchema)]
pub struct RoleSummary {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub is_system: bool,
    /// Jumlah permission yang saat ini terpasang di role ini.
    pub permissions: i64,
}

/// Body pembuatan role. `description` opsional.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRoleRequest {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// Hasil pembuatan role.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedRole {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub description: String,
    pub is_system: bool,
}

/// Satu baris katalog permission app core.
#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionEntry {
    pub key: String,
    pub name: String,
    pub is_system: bool,
}

/// Body penggantian isi permission role: set eksak, bukan tambahan.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetPermissionsRequest {
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// Daftar role app `core` beserta jumlah permission-nya.
#[utoipa::path(
    get,
    path = "/api/roles",
    responses((status = 200, description = "OK", body = [RoleSummary]))
)]
pub(crate) async fn list_roles(
    State(state): State<AppState>,
) -> Result<Json<Vec<RoleSummary>>, AppError> {
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
        "#
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(roles))
}

/// Buat role baru di app `core`. Role buatan manusia selalu `is_system = false`.
#[utoipa::path(
    post,
    path = "/api/roles",
    request_body = CreateRoleRequest,
    responses((status = 201, description = "Created", body = CreatedRole))
)]
pub(crate) async fn create_role(
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
#[utoipa::path(
    get,
    path = "/api/permissions",
    responses((status = 200, description = "OK", body = [PermissionEntry]))
)]
pub(crate) async fn list_permissions(
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
        "#
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(permissions))
}

/// Daftar key permission yang terpasang di satu role.
#[utoipa::path(
    get,
    path = "/api/roles/{id}/permissions",
    responses((status = 200, description = "OK", body = serde_json::Value))
)]
pub(crate) async fn get_role_permissions(
    State(state): State<AppState>,
    caller: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let role = domain_rbac::role_for_app(&state, caller.app.id, id).await?;
    let keys = rbac::permissions_of_role(&state.pool, role.id).await?;

    Ok(Json(json!({
        "role_id": role.id,
        "key": role.key,
        "permissions": keys,
    })))
}

/// Ganti seluruh isi permission role (set eksak).
#[utoipa::path(
    put,
    path = "/api/roles/{id}/permissions",
    request_body = SetPermissionsRequest,
    responses((status = 200, description = "OK", body = serde_json::Value))
)]
pub(crate) async fn set_role_permissions(
    State(state): State<AppState>,
    caller: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<SetPermissionsRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let role = domain_rbac::role_for_app(&state, caller.app.id, id).await?;

    domain_rbac::ensure_role_mutable(&role)?;

    // Key dinormalkan: spasi dibuang, duplikat dihapus, urutan dibuat stabil.
    let mut keys: Vec<String> = body
        .permissions
        .iter()
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
        .collect();
    keys.sort();
    keys.dedup();

    domain_rbac::ensure_can_grant(&caller, &keys)?;

    // Key yang tidak ada di katalog app ini adalah kesalahan bentuk request,
    // bukan masalah izin, jadi dijawab 400.
    for key in &keys {
        if rbac::permission_id_by_key(&state.pool, role.app_id, key)
            .await?
            .is_none()
        {
            return Err(AppError::BadRequest(format!(
                "permission \"{key}\" tidak dikenal di app ini"
            )));
        }
    }

    rbac::set_role_permissions(&state.pool, role.id, &keys).await?;

    Ok(Json(json!({
        "role_id": role.id,
        "key": role.key,
        "permissions": keys,
    })))
}

/// Hapus role non-sistem. Role `is_system` selalu ditolak 403.
#[utoipa::path(
    delete,
    path = "/api/roles/{id}",
    responses((status = 204, description = "No Content"))
)]
pub(crate) async fn remove_role(
    State(state): State<AppState>,
    caller: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let role = domain_rbac::role_for_app(&state, caller.app.id, id).await?;

    domain_rbac::ensure_role_mutable(&role)?;

    if !rbac::delete_role(&state.pool, role.id).await? {
        return Err(AppError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}
