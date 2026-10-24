//! Endpoint CRUD user versi API: daftar, buat, detail, dan ubah sebagian.
//!
//! Handler di sini hanya urusan bentuk request dan bentuk respons. Keputusan
//! boleh/tidak dan pencabutan token ada di `domain::users`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::extractor::AuthUser;
use crate::db::users::{self, UserDetail, UserStatus};
use crate::domain::users::{self as domain_users, NewUser, UserChanges};
use crate::error::AppError;
use crate::state::AppState;

/// Batas jumlah baris per halaman; cukup untuk konsol dan tetap ramah memori.
const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;
/// Batas panjang display name, sejalan dengan kolom teks biasa di konsol.
const MAX_DISPLAY_NAME: usize = 200;

/// Router endpoint user.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/{id}", get(get_user).patch(patch_user))
}

/// Parameter daftar: pencarian bebas dan paging sederhana.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub q: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Bentuk user yang dikirim ke klien. Tidak ada `password_hash` dan tidak ada
/// `pepper_version`, jadi kebocoran kolom sensitif tidak mungkin lewat sini.
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub status: &'static str,
    pub is_superadmin: bool,
    pub token_version: i32,
    /// Waktu dalam RFC 3339; format tuple bawaan `time` tidak enak dibaca klien.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<UserDetail> for UserResponse {
    fn from(user: UserDetail) -> Self {
        Self {
            id: user.id,
            email: user.email,
            display_name: user.display_name,
            status: status_name(user.status),
            is_superadmin: user.is_superadmin,
            token_version: user.token_version,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

/// Body pembuatan user.
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub is_superadmin: bool,
}

/// Body perubahan user; semua opsional tetapi minimal satu harus terisi.
///
/// `status` sengaja berupa string, bukan enum, supaya nilai asing dijawab 400
/// dengan pesan kita sendiri, bukan 422 bawaan hasil deserialisasi.
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub display_name: Option<String>,
    pub status: Option<String>,
    pub password: Option<String>,
}

/// Daftar user, terurut email.
async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<UserResponse>>, AppError> {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = query.offset.unwrap_or(0).max(0);

    let rows = users::list(&state.pool, query.q.as_deref(), limit, offset).await?;

    Ok(Json(rows.into_iter().map(UserResponse::from).collect()))
}

/// Detail satu user.
async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<UserResponse>, AppError> {
    let user = users::detail(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    Ok(Json(UserResponse::from(user)))
}

/// Buat user baru. Password minimal 12 karakter dijaga lapisan domain.
async fn create_user(
    State(state): State<AppState>,
    caller: AuthUser,
    Json(body): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
    if body.display_name.chars().count() > MAX_DISPLAY_NAME {
        return Err(AppError::BadRequest(
            "display_name terlalu panjang".to_string(),
        ));
    }

    let user = domain_users::create_user(
        &state,
        &caller,
        NewUser {
            email: body.email,
            password: body.password,
            display_name: body.display_name,
            is_superadmin: body.is_superadmin,
        },
    )
    .await?;

    Ok((StatusCode::CREATED, Json(UserResponse::from(user))))
}

/// Ubah sebagian data user. Password dan status yang berubah mencabut token lama.
async fn patch_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, AppError> {
    let status = match body.status.as_deref() {
        Some(raw) => Some(parse_status(raw)?),
        None => None,
    };

    if body.display_name.is_none() && status.is_none() && body.password.is_none() {
        return Err(AppError::BadRequest(
            "minimal satu field harus diisi".to_string(),
        ));
    }

    if body
        .display_name
        .as_ref()
        .is_some_and(|name| name.chars().count() > MAX_DISPLAY_NAME)
    {
        return Err(AppError::BadRequest(
            "display_name terlalu panjang".to_string(),
        ));
    }

    let user = domain_users::update_user(
        &state,
        id,
        UserChanges {
            display_name: body.display_name,
            status,
            password: body.password,
        },
    )
    .await?;

    Ok(Json(UserResponse::from(user)))
}

/// Nama status untuk JSON; sama dengan nilai enum Postgres.
fn status_name(status: UserStatus) -> &'static str {
    match status {
        UserStatus::Active => "active",
        UserStatus::Disabled => "disabled",
        UserStatus::Pending => "pending",
    }
}

/// Baca status dari body; nilai di luar enum ditolak sebagai 400.
fn parse_status(raw: &str) -> Result<UserStatus, AppError> {
    match raw.trim() {
        "active" => Ok(UserStatus::Active),
        "disabled" => Ok(UserStatus::Disabled),
        "pending" => Ok(UserStatus::Pending),
        lain => Err(AppError::BadRequest(format!(
            "status \"{lain}\" tidak dikenal"
        ))),
    }
}
