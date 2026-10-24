//! Middleware penegak registry: satu tempat yang memutuskan boleh atau tidak.
//!
//! Verifikasi token terjadi di sini saja, lalu hasilnya disimpan di request
//! extensions. Ekstraktor `AuthUser`/`AuthApp` tinggal membaca hasil itu, jadi
//! tanda tangan token tidak pernah dihitung dua kali untuk satu request.

use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::extractor::authenticate;
use crate::error::AppError;
use crate::rbac::registry;
use crate::state::AppState;

/// Kebijakan sadar: klaim `role` yang memuat `superadmin` dianggap memiliki
/// semua permission. Token tetap wajib sah dan `aud`-nya tetap harus cocok
/// dengan app route, jadi bypass ini tidak membuka jalan lintas app.
const SUPERADMIN: &str = "superadmin";

/// Jalankan penegakan registry untuk satu request.
///
/// Fail-closed: route yang tidak ada di registry dijawab 500 dan dicatat di log.
/// Itu disengaja supaya route baru yang lupa didaftarkan langsung terlihat,
/// bukan diam-diam lolos tanpa permission.
pub async fn enforce(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    let method = request.method().clone();

    let Some(path) = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
    else {
        tracing::error!(%method, "request tidak punya MatchedPath; router tidak lengkap");
        return AppError::Internal.into_response();
    };

    let Some(route) = registry::find(&method, &path) else {
        tracing::error!(%method, path = %path, "route belum terdaftar di registry");
        return AppError::Internal.into_response();
    };

    let Some(permission) = route.permission else {
        return next.run(request).await;
    };

    // Route berpermission selalu terikat satu app; tanpa slug tidak ada yang
    // bisa diverifikasi, jadi perlakukan sebagai kesalahan konfigurasi.
    let Some(slug) = route.scope.app_slug() else {
        tracing::error!(%method, path = %path, "route berpermission tanpa app scope");
        return AppError::Internal.into_response();
    };

    let auth = match authenticate(&state, request.headers(), slug).await {
        Ok(auth) => auth,
        Err(err) => return err.into_response(),
    };

    if !allowed(&auth.claims, permission) {
        return AppError::Forbidden.into_response();
    }

    request.extensions_mut().insert(auth);
    next.run(request).await
}

/// Superadmin lolos tanpa melihat scope; selain itu permission harus ada di
/// klaim `scope` yang sudah dihitung saat token diterbitkan.
fn allowed(claims: &crate::auth::jwt::Claims, permission: &str) -> bool {
    claims.role.iter().any(|role| role == SUPERADMIN)
        || claims.scope.iter().any(|scope| scope == permission)
}
