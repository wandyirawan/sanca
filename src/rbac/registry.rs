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
///
/// Tanpa `audit_action`: tidak setiap route perlu meninggalkan jejak, dan
/// action yang tidak berbentuk `resource.verb` hanya jadi noise di layar audit.
const fn protected(method: Method, path: &'static str, permission: &'static str) -> RouteDef {
    RouteDef {
        method,
        path,
        access: Access::Permission(permission),
        scope: AppScope::CoreOnly,
        audit_action: None,
    }
}

/// Route terproteksi yang juga dicatat middleware audit.
///
/// `action` ditulis `resource.verb` huruf kecil supaya kolom aksi di layar
/// audit terbaca sebagai kalimat kerja, bukan sebagai nama permission.
const fn protected_audit(
    method: Method,
    path: &'static str,
    permission: &'static str,
    action: &'static str,
) -> RouteDef {
    RouteDef {
        method,
        path,
        access: Access::Permission(permission),
        scope: AppScope::CoreOnly,
        audit_action: Some(action),
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
    // Halaman consent OAuth2 butuh sesi console (aud `core`) tetapi tidak menuntut
    // permission: yang menentukan boleh atau tidak adalah keputusan pengguna di
    // halaman itu sendiri, dan app tujuan diperiksa di domain.
    authenticated(Method::GET, "/oauth/authorize"),
    authenticated(Method::POST, "/oauth/authorize"),
    // Console: halaman login dan logout tidak butuh sesi. Logout tetap publik
    // karena satu-satunya bukti yang dipakai adalah cookie refresh; memaksa
    // access token yang sah di sini akan membuat pengguna dengan token
    // kedaluwarsa tidak bisa keluar. CSRF tetap divalidasi di handler.
    public(Method::GET, "/console/login"),
    public(Method::POST, "/console/login"),
    public(Method::POST, "/console/logout"),
    public(Method::GET, "/assets/{*path}"),
    // Dokumentasi OpenAPI (publik). Entri terpisah per template route yang
    // dipasang Swagger UI supaya middleware tidak fail-closed (500).
    public(Method::GET, "/openapi.json"),
    public(Method::GET, "/docs"),
    public(Method::GET, "/docs/"),
    public(Method::GET, "/docs/{*rest}"),
    // Dashboard hanya butuh login; setiap menu di dalamnya diperiksa `can()`.
    authenticated(Method::GET, "/console"),
    // Layar pengguna: membaca daftar/detail cukup `user:read`, sedangkan form
    // ubah dan kedua aksi tulis menuntut `user:write`. Route form tetap
    // didaftarkan supaya halaman yang dirender tanpa JavaScript pun melewati
    // penegakan yang sama, bukan hanya tombolnya disembunyikan.
    protected_audit(Method::GET, "/console/users", "user:read", "user.read"),
    protected_audit(Method::POST, "/console/users", "user:write", "user.create"),
    protected(Method::GET, "/console/users/rows", "user:read"),
    protected(Method::GET, "/console/users/new", "user:write"),
    protected_audit(Method::GET, "/console/users/{id}", "user:read", "user.read"),
    protected_audit(
        Method::POST,
        "/console/users/{id}",
        "user:write",
        "user.update",
    ),
    protected(Method::GET, "/console/users/{id}/edit", "user:write"),
    // Layar aplikasi: daftar dan fragmen baris cukup `app:read`; membuat app dan
    // merotasi secret menuntut `app:write`. Route rotasi didaftarkan sebagai
    // POST tersendiri supaya penegakan tidak bergantung pada tombol yang
    // disembunyikan template.
    protected_audit(Method::GET, "/console/apps", "app:read", "app.read"),
    protected(Method::GET, "/console/apps/rows", "app:read"),
    protected(Method::GET, "/console/apps/new", "app:write"),
    protected_audit(Method::POST, "/console/apps", "app:write", "app.create"),
    protected_audit(
        Method::POST,
        "/console/apps/{id}/rotate",
        "app:write",
        "app.rotate_secret",
    ),
    // Layar RBAC: matriks role × permission cukup `role:read`; menyimpan izin
    // satu role menuntut `role:write`. Route POST terpisah supaya penegakan
    // tidak bergantung pada tombol yang disembunyikan template.
    protected_audit(Method::GET, "/console/rbac", "role:read", "role.read"),
    protected_audit(
        Method::POST,
        "/console/rbac/roles/{id}/permissions",
        "role:write",
        "role.update_permissions",
    ),
    // Jejak audit hanya bisa dibaca, tidak ada route tulis dari console.
    protected_audit(Method::GET, "/console/audit", "audit:read", "audit.read"),
    authenticated(Method::GET, "/api/auth/me"),
    protected_audit(Method::GET, "/api/roles", "role:read", "role.read"),
    protected_audit(Method::POST, "/api/roles", "role:write", "role.create"),
    protected(Method::GET, "/api/permissions", "role:read"),
    protected(Method::GET, "/api/roles/{id}/permissions", "role:read"),
    protected_audit(
        Method::PUT,
        "/api/roles/{id}/permissions",
        "role:write",
        "role.update_permissions",
    ),
    protected_audit(
        Method::DELETE,
        "/api/roles/{id}",
        "role:write",
        "role.delete",
    ),
    protected_audit(Method::GET, "/api/users", "user:read", "user.read"),
    protected_audit(Method::POST, "/api/users", "user:write", "user.create"),
    protected_audit(Method::GET, "/api/users/{id}", "user:read", "user.read"),
    protected_audit(
        Method::PATCH,
        "/api/users/{id}",
        "user:write",
        "user.update",
    ),
    protected_audit(
        Method::POST,
        "/api/users/{id}/roles",
        "role:write",
        "role.assign",
    ),
    protected_audit(
        Method::DELETE,
        "/api/users/{id}/roles/{role_id}",
        "role:write",
        "role.revoke",
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
