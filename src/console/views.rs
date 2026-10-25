//! Struct template askama untuk console.
//!
//! Setiap struct hanya membawa data yang memang dibaca templatenya. Tidak ada
//! konteks global: `can()` membaca scope yang sudah terverifikasi di token sesi,
//! bukan hasil query baru.

use askama::Template;

use crate::console::helpers;

/// Halaman login. Dipakai dua kali: form kosong dan form yang gagal.
#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginPage {
    pub csrf: String,
    pub email: String,
    pub error: Option<String>,
}

/// Halaman dashboard. `can()` dipanggil dari layout dan partial nav.
#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardPage {
    pub csrf: String,
    pub user_name: String,
    pub user_email: String,
    pub users_count: i64,
    pub apps_count: i64,
    pub roles_count: i64,
    pub roles: Vec<String>,
    pub scope: Vec<String>,
}

impl DashboardPage {
    /// Wrapper tipis supaya template cukup menulis `{% if can("user:read") %}`.
    pub fn can(&self, permission: &str) -> bool {
        helpers::can(&self.scope, &self.roles, permission)
    }
}

/// Halaman error berdiri sendiri, tanpa sidebar.
#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorPage {
    pub title: &'static str,
    pub message: String,
}
