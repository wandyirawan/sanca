//! Aturan bisnis RBAC: siapa boleh memberi permission apa, dan role mana yang
//! tidak boleh disentuh.
//!
//! Tiga guard di sini adalah inti pencegahan eskalasi hak akses:
//!
//! 1. `ensure_can_grant` — pemegang `role:write` tidak otomatis boleh membagi
//!    permission yang tidak ia miliki sendiri.
//! 2. `ensure_can_assign_role` — role yang diberikan harus seluruh permission-nya
//!    bagian dari scope pemberi, dan role sistem `superadmin` terlarang.
//! 3. `ensure_role_mutable` — role `is_system` beku total, termasuk bagi
//!    superadmin.
//!
//! Ketiga fungsi mengembalikan `AppError::Forbidden` (403) saat dilanggar; alasan
//! detailnya hanya masuk log supaya klien tidak bisa memetakan batas internal.

use std::collections::BTreeSet;

use uuid::Uuid;

use crate::auth::extractor::AuthUser;
use crate::db::rbac::{self, Role};
use crate::domain::users::is_superadmin;
use crate::error::AppError;
use crate::state::AppState;

/// Kumpulan permission yang benar-benar dipegang pemanggil menurut klaim token.
///
/// Yang dipakai klaim `scope`, bukan hasil query ulang ke database: middleware
/// menegakkan hal yang sama, jadi keputusan di sini selalu sepakat dengan pintu
/// masuknya.
fn caller_scope(caller: &AuthUser) -> BTreeSet<&str> {
    caller.claims.scope.iter().map(String::as_str).collect()
}

/// Pastikan pemanggil berhak memberikan seluruh `keys`.
///
/// Superadmin bebas. Selain itu setiap key wajib ada di scope pemanggil sendiri,
/// sehingga `role:write` bukan lagi tiket untuk menaikkan hak akses diri sendiri
/// atau orang lain di luar yang sudah dimilikinya.
pub fn ensure_can_grant(caller: &AuthUser, keys: &[String]) -> Result<(), AppError> {
    if is_superadmin(caller) {
        return Ok(());
    }

    let scope = caller_scope(caller);

    if let Some(ditolak) = keys.iter().find(|key| !scope.contains(key.as_str())) {
        tracing::warn!(
            actor = %caller.claims.sub,
            permission = %ditolak,
            "pemberian permission ditolak: di luar scope pemberi"
        );
        return Err(AppError::Forbidden);
    }

    Ok(())
}

/// Pastikan role boleh diubah isinya atau dihapus.
///
/// Role `is_system` (misalnya `superadmin`) adalah bagian dari kontrak keamanan
/// service ini: mengubah isinya berarti mengubah arti seluruh token yang sudah
/// terbit. Karena itu role sistem beku untuk semua pemanggil, termasuk superadmin.
pub fn ensure_role_mutable(role: &Role) -> Result<(), AppError> {
    if role.is_system {
        tracing::warn!(
            role = %role.key,
            role_id = %role.id,
            "perubahan role ditolak: role is_system bersifat beku"
        );
        return Err(AppError::Forbidden);
    }

    Ok(())
}

/// Pastikan pemanggil boleh memberikan `role` kepada user lain.
///
/// Superadmin bebas. Selain itu role tidak boleh role sistem/`superadmin`, dan
/// seluruh permission role tersebut harus subset dari scope pemanggil — kalau
/// tidak, pemberian role sama dengan memberi permission yang belum ia punya.
pub async fn ensure_can_assign_role(
    state: &AppState,
    caller: &AuthUser,
    role: &Role,
) -> Result<(), AppError> {
    if is_superadmin(caller) {
        return Ok(());
    }

    // Aturan 4: role superadmin tidak pernah bisa diberikan oleh non-superadmin,
    // bahkan kalau kebetulan isinya kosong.
    if role.is_system || role.key == "superadmin" {
        tracing::warn!(
            actor = %caller.claims.sub,
            role = %role.key,
            "pemberian role ditolak: role sistem hanya untuk superadmin"
        );
        return Err(AppError::Forbidden);
    }

    let keys = rbac::permissions_of_role(&state.pool, role.id).await?;
    let scope = caller_scope(caller);

    if let Some(ditolak) = keys.iter().find(|key| !scope.contains(key.as_str())) {
        tracing::warn!(
            actor = %caller.claims.sub,
            role = %role.key,
            permission = %ditolak,
            "pemberian role ditolak: permission role di luar scope pemberi"
        );
        return Err(AppError::Forbidden);
    }

    Ok(())
}

/// Pastikan pemanggil boleh mengubah keanggotaan sebuah role.
///
/// Untuk role biasa tidak ada batas tambahan di sini — `role:write` sudah cukup.
/// Role sistem hanya boleh diurus superadmin, karena mencabutnya sama dengan
/// mengubah siapa yang berkuasa penuh di service ini.
pub fn ensure_can_touch_membership(caller: &AuthUser, role: &Role) -> Result<(), AppError> {
    if role.is_system && !is_superadmin(caller) {
        tracing::warn!(
            actor = %caller.claims.sub,
            role = %role.key,
            "perubahan keanggotaan role ditolak: hanya superadmin"
        );
        return Err(AppError::Forbidden);
    }

    Ok(())
}

/// Ambil role yang memang milik app pemanggil.
///
/// Role app lain diperlakukan seperti tidak ada (404), bukan 403: keberadaannya
/// bukan urusan app ini.
pub async fn role_for_app(state: &AppState, app_id: Uuid, role_id: Uuid) -> Result<Role, AppError> {
    let role = rbac::role_by_id(&state.pool, role_id)
        .await?
        .ok_or(AppError::NotFound)?;

    if role.app_id != app_id {
        return Err(AppError::NotFound);
    }

    Ok(role)
}

/// Ubah `sub` klaim menjadi id user untuk kolom `granted_by`.
///
/// Token yang lolos middleware selalu berisi uuid, jadi kegagalan di sini berarti
/// ada yang salah di sisi kita, bukan di sisi klien.
pub fn caller_id(caller: &AuthUser) -> Result<Uuid, AppError> {
    Uuid::parse_str(&caller.claims.sub).map_err(|err| {
        tracing::error!(error = %err, sub = %caller.claims.sub, "sub token bukan uuid");
        AppError::Internal
    })
}
