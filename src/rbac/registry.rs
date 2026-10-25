//! Daftar route yang dilayani beserta syarat aksesnya.
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

/// Syarat akses sebuah route. Tiga arti yang sengaja dibedakan supaya
/// "wajib login" tidak lagi dipaksa berarti "wajib punya permission".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Tanpa token sama sekali.
    Public,
    /// Token wajib sah (aud cocok), tetapi tidak memerlukan permission apa pun.
    Authenticated,
    /// Token wajib sah DAN klaim scope memuat permission ini (kecuali superadmin).
    Permission(&'static str),
}

/// Satu baris registry: route apa, syarat akses apa, dan app siapa.
#[derive(Debug, Clone)]
pub struct RouteDef {
    pub method: Method,
    pub path: &'static str,
    pub access: Access,
    pub scope: AppScope,
    /// Nama aksi audit kalau nanti route ini dicatat; belum dipakai middleware.
    pub audit_action: Option<&'static str>,
}

/// Route publik: tidak ada token, tidak ada app.
const fn public(method: Method, path: &'static str) -> RouteDef {
    RouteDef {
        method,
        path,
        access: Access::Public,
        scope: AppScope::Public,
        audit_action: None,
    }
}

/// Route app `core` yang wajib login tetapi tidak menuntut permission khusus.
const fn authenticated(method: Method, path: &'static str) -> RouteDef {
    RouteDef {
        method,
        path,
        access: Access::Authenticated,
        scope: AppScope::CoreOnly,
        audit_action: None,
    }
}

/// Route terproteksi milik app `core` dengan satu permission wajib.
const fn protected(method: Method, path: &'static str, permission: &'static str) -> RouteDef {
    RouteDef {
        method,
        path,
        access: Access::Permission(permission),
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
///
/// `GET /api/auth/me` hanya `Authenticated`: isinya identitas pemilik token
/// sendiri, jadi setiap user yang sudah login berhak membacanya tanpa perlu
/// permission tambahan.
pub const ROUTES: &[RouteDef] = &[
    public(Method::GET, "/healthz"),
    public(Method::GET, "/.well-known/jwks.json"),
    public(Method::POST, "/api/auth/login"),
    public(Method::POST, "/api/auth/refresh"),
    public(Method::POST, "/api/auth/logout"),
    public(Method::POST, "/api/oauth/token"),
    authenticated(Method::GET, "/api/auth/me"),
    protected(Method::GET, "/api/roles", "role:read"),
    protected(Method::POST, "/api/roles", "role:write"),
    protected(Method::GET, "/api/permissions", "role:read"),
    protected(Method::GET, "/api/roles/{id}/permissions", "role:read"),
    protected(Method::PUT, "/api/roles/{id}/permissions", "role:write"),
    protected(Method::DELETE, "/api/roles/{id}", "role:write"),
    protected(Method::GET, "/api/users", "user:read"),
    protected(Method::POST, "/api/users", "user:write"),
    protected(Method::GET, "/api/users/{id}", "user:read"),
    protected(Method::PATCH, "/api/users/{id}", "user:write"),
    protected(Method::POST, "/api/users/{id}/roles", "role:write"),
    protected(
        Method::DELETE,
        "/api/users/{id}/roles/{role_id}",
        "role:write",
    ),
];

/// Cari definisi route berdasarkan method dan template path hasil `MatchedPath`.
pub fn find(method: &Method, path: &str) -> Option<&'static RouteDef> {
    ROUTES
        .iter()
        .find(|route| route.method == *method && route.path == path)
}

/// Daftar permission unik dan terurut; dipakai `sync` untuk mengisi tabel.
///
/// Sumbernya semua `Access::Permission`, ditambah `auth:me` yang sengaja tetap
/// didaftarkan walau route `/api/auth/me` tidak mewajibkannya: console nanti
/// butuh baris itu untuk menampilkan matrix role × permission, dan role lama
/// yang sudah memegang `auth:me` tidak kehilangan barisnya.
pub fn permissions() -> Vec<&'static str> {
    ROUTES
        .iter()
        .filter_map(|route| match route.access {
            Access::Permission(permission) => Some(permission),
            Access::Public | Access::Authenticated => None,
        })
        .chain(std::iter::once("auth:me"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
