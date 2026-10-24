//! Daftar route yang dilayani beserta permission yang diwajibkannya.
//!
//! Registry adalah satu-satunya sumber kebenaran. Middleware menolak (500)
//! setiap route yang tidak terdaftar di sini, justru supaya lupa mendaftar
//! langsung terlihat saat pengembangan, bukan lolos tanpa otorisasi.

use std::collections::BTreeSet;

use axum::http::Method;

/// Cakupan app dari sebuah route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppScope {
    /// Boleh diakses tanpa token dan tidak terikat app mana pun.
    Public,
    /// Hanya untuk app `core`; token wajib ber-aud `core`.
    CoreOnly,
}

impl AppScope {
    /// Slug app pemilik route. Route publik tidak punya app, jadi `None`.
    pub const fn app_slug(self) -> Option<&'static str> {
        match self {
            AppScope::Public => None,
            AppScope::CoreOnly => Some("core"),
        }
    }
}

/// Satu baris registry: route apa, permission apa, dan app siapa.
#[derive(Debug, Clone)]
pub struct RouteDef {
    pub method: Method,
    pub path: &'static str,
    /// `None` berarti route publik, tidak butuh token.
    pub permission: Option<&'static str>,
    pub scope: AppScope,
    /// Nama aksi audit kalau nanti route ini dicatat; belum dipakai middleware.
    pub audit_action: Option<&'static str>,
}

/// Route publik: tidak ada token, tidak ada app.
const fn public(method: Method, path: &'static str) -> RouteDef {
    RouteDef {
        method,
        path,
        permission: None,
        scope: AppScope::Public,
        audit_action: None,
    }
}

/// Route terproteksi milik app `core` dengan satu permission wajib.
const fn protected(method: Method, path: &'static str, permission: &'static str) -> RouteDef {
    RouteDef {
        method,
        path,
        permission: Some(permission),
        scope: AppScope::CoreOnly,
        audit_action: Some(permission),
    }
}

/// Semua route yang dilayani router API.
///
/// `POST /api/auth/logout` tetap publik karena satu-satunya bukti yang dipakai
/// adalah refresh token di body; meminta access token di sini hanya menambah
/// langkah tanpa menambah keamanan, dan klien yang access token-nya sudah
/// kedaluwarsa tetap harus bisa mencabut sesinya.
pub const ROUTES: &[RouteDef] = &[
    public(Method::GET, "/healthz"),
    public(Method::GET, "/.well-known/jwks.json"),
    public(Method::POST, "/api/auth/login"),
    public(Method::POST, "/api/auth/refresh"),
    public(Method::POST, "/api/auth/logout"),
    public(Method::POST, "/api/oauth/token"),
    protected(Method::GET, "/api/auth/me", "auth:me"),
    protected(Method::GET, "/api/roles", "role:read"),
    protected(Method::POST, "/api/roles", "role:write"),
    protected(Method::GET, "/api/permissions", "role:read"),
];

/// Cari definisi route berdasarkan method dan template path hasil `MatchedPath`.
pub fn find(method: &Method, path: &str) -> Option<&'static RouteDef> {
    ROUTES
        .iter()
        .find(|route| route.method == *method && route.path == path)
}

/// Daftar permission unik dan terurut; dipakai `sync` untuk mengisi tabel.
pub fn permissions() -> Vec<&'static str> {
    ROUTES
        .iter()
        .filter_map(|route| route.permission)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
