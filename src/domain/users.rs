//! Aturan bisnis seputar user: siapa boleh membuat apa, dan kapan token dicabut.
//!
//! Lapisan ini sengaja tipis dan berbentuk fungsi async biasa. `db::users` tetap
//! hanya berisi SQL; keputusan seperti "hanya superadmin yang boleh membuat
//! superadmin" dan "ganti password berarti cabut token" tinggal di sini.

use uuid::Uuid;

use crate::auth::extractor::AuthUser;
use crate::auth::password::{PasswordError, hash_password};
use crate::db::rbac;
use crate::db::users::{self, UserDetail, UserStatus};
use crate::error::AppError;
use crate::state::AppState;

/// Data yang dibutuhkan untuk membuat user baru.
pub struct NewUser {
    pub email: String,
    pub password: String,
    pub display_name: String,
    pub is_superadmin: bool,
}

/// Perubahan opsional pada satu user. Paling sedikit satu field harus terisi;
/// syarat itu diperiksa lapisan API karena bentuk request bukan urusan domain.
pub struct UserChanges {
    pub display_name: Option<String>,
    pub status: Option<UserStatus>,
    pub password: Option<String>,
}

/// Apakah pemanggil memegang klaim role `superadmin`?
///
/// Yang dipakai klaim token, bukan kolom `users.is_superadmin`: middleware
/// penegakan juga memakai klaim yang sama, jadi kedua tempat selalu sepakat.
pub fn is_superadmin(caller: &AuthUser) -> bool {
    caller.claims.role.iter().any(|role| role == "superadmin")
}

/// Buat user baru. Hanya superadmin yang boleh membuat superadmin lain.
pub async fn create_user(
    state: &AppState,
    caller: &AuthUser,
    input: NewUser,
) -> Result<UserDetail, AppError> {
    let email = input.email.trim().to_string();
    if email.is_empty() {
        return Err(AppError::BadRequest("email wajib diisi".to_string()));
    }

    if input.is_superadmin && !is_superadmin(caller) {
        return Err(AppError::Forbidden);
    }

    let password_hash = hash_password(&input.password, &state.config.argon2_pepper)
        .map_err(password_error_to_app)?;

    let display_name = input.display_name.trim();

    // Transaksi supaya user superadmin tidak pernah lahir tanpa role-nya.
    let mut tx = state.pool.begin().await?;

    let user = users::insert_with_flags(
        &mut *tx,
        &email,
        &password_hash,
        display_name,
        input.is_superadmin,
        state.config.argon2_pepper_version,
    )
    .await
    .map_err(insert_error)?;

    if input.is_superadmin && !rbac::assign_system_superadmin(&mut tx, user.id).await? {
        tracing::error!(user_id = %user.id, "role superadmin tidak ada; pembuatan user dibatalkan");
        return Err(AppError::Internal);
    }

    tx.commit().await?;

    users::detail(&state.pool, user.id)
        .await?
        .ok_or(AppError::Internal)
}

/// Ubah profil, status, dan/atau password satu user.
///
/// `token_version` naik setiap kali password atau status berubah, sehingga
/// token yang sudah terbit langsung tidak berlaku.
pub async fn update_user(
    state: &AppState,
    id: Uuid,
    changes: UserChanges,
) -> Result<UserDetail, AppError> {
    let current = users::detail(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)?;

    if let Some(password) = changes.password.as_deref() {
        let hash =
            hash_password(password, &state.config.argon2_pepper).map_err(password_error_to_app)?;
        users::set_password(&state.pool, id, &hash)
            .await?
            .ok_or(AppError::NotFound)?;
    }

    if let Some(status) = changes.status {
        let berubah = status != current.status;

        if status == UserStatus::Disabled && berubah {
            users::disable(&state.pool, id).await?;
        } else {
            users::update_profile(&state.pool, id, None, Some(status))
                .await?
                .ok_or(AppError::NotFound)?;

            // Akun yang diaktifkan kembali juga harus memaksa login ulang:
            // token dari masa sebelum penonaktifan tidak boleh hidup lagi.
            if berubah {
                users::bump_token_version(&state.pool, id).await?;
            }
        }
    }

    if let Some(display_name) = changes.display_name.as_deref() {
        users::update_profile(&state.pool, id, Some(display_name.trim()), None)
            .await?
            .ok_or(AppError::NotFound)?;
    }

    users::detail(&state.pool, id)
        .await?
        .ok_or(AppError::NotFound)
}

/// Terjemahkan error password menjadi 400 atau 500 sesuai penyebabnya.
fn password_error_to_app(err: PasswordError) -> AppError {
    match err {
        PasswordError::TooShort => AppError::BadRequest(err.to_string()),
        PasswordError::Rejected => AppError::BadRequest(err.to_string()),
        PasswordError::PepperUnavailable | PasswordError::UnsupportedPepperVersion(_) => {
            tracing::error!(error = %err, "pepper tidak bisa dipakai untuk hashing");
            AppError::Internal
        }
        PasswordError::InvalidHash => AppError::Internal,
    }
}

/// Email duplikat adalah konflik, bukan kesalahan server.
fn insert_error(err: sqlx::Error) -> AppError {
    if err
        .as_database_error()
        .is_some_and(|db| db.is_unique_violation())
    {
        return AppError::Conflict("user dengan email itu sudah ada".to_string());
    }

    tracing::error!(error = %err, "gagal menyimpan user baru");
    AppError::Internal
}
