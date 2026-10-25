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
    /// User berstatus `active`; akun nonaktif tetap dihitung terpisah oleh layar pengguna.
    pub users_active: i64,
    pub apps_count: i64,
    pub roles_count: i64,
    pub permissions_count: i64,
    /// Sesi yang belum dicabut dan belum kedaluwarsa.
    pub sessions_active: i64,
    /// Event audit dalam 24 jam terakhir.
    pub audit_24h: i64,
    pub roles: Vec<String>,
    pub scope: Vec<String>,
}

impl DashboardPage {
    /// Wrapper tipis supaya template cukup menulis `{% if can("user:read") %}`.
    pub fn can(&self, permission: &str) -> bool {
        helpers::can(&self.scope, &self.roles, permission)
    }
}

/// Satu baris tabel user. Tidak ada `password_hash` di sini — bukan karena
/// template menjanjikan, tapi karena datanya memang tidak pernah diambil.
pub struct UserRowView {
    pub id: String,
    pub email: String,
    pub display_name: String,
    /// `active` | `disabled` | `pending`, dipakai template untuk memilih badge.
    pub status: &'static str,
    pub is_superadmin: bool,
    pub role_count: i64,
}

/// Data yang dipakai bersama oleh halaman daftar dan fragmen barisnya.
///
/// Perhitungan pager dikerjakan di sini supaya template tidak berisi aritmetika
/// offset dan kedua tampilan (halaman penuh, fragmen HTMX) selalu sepakat.
pub struct UsersData {
    pub rows: Vec<UserRowView>,
    pub q: String,
    pub limit: i64,
    pub offset: i64,
    pub total: i64,
    /// Apakah database punya user sama sekali? Membedakan "belum ada data"
    /// dari "filter tidak menemukan apa pun" — dua empty state yang berbeda.
    pub any_user: bool,
    /// Menentukan tombol aksi (tambah/ubah) dirender atau tidak. Ini UX saja;
    /// penegakan sebenarnya tetap di registry route.
    pub can_write: bool,
}

impl UsersData {
    /// Nomor baris pertama yang tampil; 0 kalau halaman kosong.
    pub fn first(&self) -> i64 {
        if self.rows.is_empty() {
            0
        } else {
            self.offset + 1
        }
    }

    /// Nomor baris terakhir yang tampil.
    pub fn last(&self) -> i64 {
        self.offset + self.rows.len() as i64
    }

    pub fn has_prev(&self) -> bool {
        self.offset > 0
    }

    pub fn has_next(&self) -> bool {
        self.last() < self.total
    }

    pub fn prev_offset(&self) -> i64 {
        (self.offset - self.limit).max(0)
    }

    pub fn next_offset(&self) -> i64 {
        self.offset + self.limit
    }

    /// Label ringkas untuk pager: "1-20 dari 57".
    pub fn range_label(&self) -> String {
        format!("{}-{} dari {}", self.first(), self.last(), self.total)
    }
}

/// Notifikasi hasil aksi. Dibawa lewat query `?ok=`/`?err=` setelah redirect,
/// bukan `HX-Trigger`: dengan begitu pesan tetap muncul walau HTMX mati.
pub struct Notice {
    /// `success` atau `error`, dipetakan template ke kelas `alert`.
    pub kind: &'static str,
    pub text: String,
}

/// Halaman penuh daftar user. `can()` dipanggil layout dan partial nav.
#[derive(Template)]
#[template(path = "users/list.html")]
pub struct UsersPage {
    pub csrf: String,
    pub user_name: String,
    pub user_email: String,
    pub roles: Vec<String>,
    pub scope: Vec<String>,
    pub data: UsersData,
    pub notice: Option<Notice>,
}

impl UsersPage {
    pub fn can(&self, permission: &str) -> bool {
        helpers::can(&self.scope, &self.roles, permission)
    }
}

/// Fragmen yang dikirim ke HTMX: `<tbody>` ditambah pager out-of-band.
#[derive(Template)]
#[template(path = "users/rows_response.html")]
pub struct UsersRows {
    pub data: UsersData,
}

/// Isi form create/edit, dipakai dua pembungkus (modal dan halaman penuh).
pub struct UserFormFields {
    /// `create` atau `edit`; menentukan field mana yang tampil.
    pub mode: &'static str,
    pub action: String,
    pub email: String,
    pub display_name: String,
    /// Status hanya bisa diubah saat edit.
    pub status: &'static str,
    pub email_error: Option<String>,
    pub name_error: Option<String>,
    pub password_error: Option<String>,
    pub general_error: Option<String>,
}

impl UserFormFields {
    pub fn is_edit(&self) -> bool {
        self.mode == "edit"
    }
}

/// Form dalam `<dialog>` — respons untuk permintaan HTMX.
#[derive(Template)]
#[template(path = "users/form.html")]
pub struct UserFormModal {
    pub csrf: String,
    pub form: UserFormFields,
}

/// Form sebagai halaman penuh — jalur tanpa JavaScript.
#[derive(Template)]
#[template(path = "users/form_page.html")]
pub struct UserFormPage {
    pub csrf: String,
    pub user_name: String,
    pub user_email: String,
    pub roles: Vec<String>,
    pub scope: Vec<String>,
    pub form: UserFormFields,
}

impl UserFormPage {
    pub fn can(&self, permission: &str) -> bool {
        helpers::can(&self.scope, &self.roles, permission)
    }
}

/// Atribut user yang boleh dilihat konsol; tanpa `password_hash`.
pub struct UserDetailFields {
    pub email: String,
    pub display_name: String,
    pub status: &'static str,
    pub is_superadmin: bool,
    pub token_version: i32,
    pub created_at: String,
    pub role_names: Vec<String>,
}

/// Modal detail user (respons HTMX).
#[derive(Template)]
#[template(path = "users/detail.html")]
pub struct UserDetailModal {
    pub detail: UserDetailFields,
}

/// Halaman error berdiri sendiri, tanpa sidebar.
#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorPage {
    pub title: &'static str,
    pub message: String,
}
