//! Matriks role × permission untuk app `core`.
//!
//! Satu halaman, satu tabel: baris adalah permission dari katalog registry,
//! kolom adalah role. Tiap kolom punya form sendiri (disatukan ke input lewat
//! atribut `form`), jadi halaman tetap bisa dipakai tanpa JavaScript dan satu
//! tombol simpan tidak pernah mengirim izin milik role lain.
//!
//! Aturan "siapa boleh memberi apa" tetap milik `domain::rbac`. Handler di sini
//! hanya memanggil `ensure_role_mutable` dan `ensure_can_grant`; tidak ada
//! salinan aturan eskalasi di lapisan tampilan.

use std::collections::{HashMap, HashSet};

use askama::Template;
use axum::Extension;
use axum::Form;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::extractor::AuthUser;
use crate::console::ConsoleSession;
use crate::console::helpers;
use crate::console::views::{ErrorPage, Notice};
use crate::db::apps as db_apps;
use crate::db::rbac as db_rbac;
use crate::db::users;
use crate::domain::rbac as domain_rbac;
use crate::error::AppError;
use crate::middleware::csrf;
use crate::state::AppState;

/// App pemilik seluruh role dan permission console.
const CORE_APP: &str = "core";

/// Router layar RBAC. Route-nya terdaftar di `rbac::registry`.
pub fn router() -> Router<AppState> {
    Router::new().route("/console/rbac", get(matrix)).route(
        "/console/rbac/roles/{id}/permissions",
        post(save_permissions),
    )
}

/// Parameter notifikasi setelah redirect.
#[derive(Debug, Deserialize)]
pub struct NoticeQuery {
    #[serde(default)]
    pub ok: String,
}

/// Satu sel matriks, sudah lengkap dengan atribut aksesibilitas.
///
/// Form dikirim sebagai pasangan kunci-nilai (`permissions=a&permissions=b`),
/// bukan struct: `serde_urlencoded` tidak bisa memetakan field berulang ke
/// `Vec<String>`. Daftar kosong berarti mencabut semua permission role.
pub struct MatrixCell {
    pub input_id: String,
    /// Nama field checkbox: `perm_<role_id>`.
    pub name: String,
    /// Key permission yang dikirim kalau dicentang.
    pub value: String,
    pub checked: bool,
    pub disabled: bool,
    /// Alasan sel dinonaktifkan; tampil sebagai tooltip.
    pub title: String,
    /// Label tersembunyi yang terkait lewat `for`.
    pub label: String,
}

/// Satu baris permission beserta sel untuk tiap kolom role.
pub struct MatrixRow {
    pub key: String,
    pub description: String,
    pub cells: Vec<MatrixCell>,
}

/// Satu kolom role.
pub struct MatrixRole {
    pub id: String,
    pub key: String,
    pub name: String,
    pub is_system: bool,
}

/// Data matriks yang dibaca template.
pub struct MatrixData {
    pub rows: Vec<MatrixRow>,
    pub roles: Vec<MatrixRole>,
    /// Menentukan tombol simpan dirender. Penegakan sebenarnya tetap di registry
    /// dan di domain guard.
    pub can_write: bool,
    /// Katalog kosong berarti sync registry belum berjalan.
    pub any_permission: bool,
}

/// Halaman matriks.
#[derive(Template)]
#[template(path = "rbac/matrix.html")]
pub struct MatrixPage {
    pub csrf: String,
    pub user_name: String,
    pub user_email: String,
    pub roles: Vec<String>,
    pub scope: Vec<String>,
    pub data: MatrixData,
    pub notice: Option<Notice>,
}

impl MatrixPage {
    pub fn can(&self, permission: &str) -> bool {
        helpers::can(&self.scope, &self.roles, permission)
    }
}

/// Identitas pemilik sesi untuk shell console.
struct Viewer {
    name: String,
    email: String,
    roles: Vec<String>,
    scope: Vec<String>,
}

impl Viewer {
    fn can(&self, permission: &str) -> bool {
        helpers::can(&self.scope, &self.roles, permission)
    }

    fn is_superadmin(&self) -> bool {
        self.roles.iter().any(|role| role == helpers::SUPERADMIN)
    }
}

/// GET /console/rbac — matriks role × permission app core.
async fn matrix(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
    Query(query): Query<NoticeQuery>,
) -> Response {
    let viewer = match viewer(&state, &session).await {
        Ok(viewer) => viewer,
        Err(response) => return *response,
    };

    let data = match matrix_data(&state, &viewer).await {
        Ok(data) => data,
        Err(err) => return err.into_response(),
    };

    let (token, _) = csrf::token(&jar);
    let page = MatrixPage {
        csrf: token.clone(),
        user_name: viewer.name,
        user_email: viewer.email,
        roles: viewer.roles,
        scope: viewer.scope,
        data,
        notice: notice(&query),
    };

    with_csrf(page, jar, token, &state)
}

/// POST /console/rbac/roles/{id}/permissions — ganti set izin satu role.
async fn save_permissions(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
    Path(id): Path<String>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let csrf_token = pairs
        .iter()
        .find(|(key, _)| key == csrf::FIELD_NAME)
        .map(|(_, value)| value.as_str())
        .unwrap_or_default();

    if !csrf::matches(&jar, csrf_token) {
        return forbidden(
            "Token keamanan form tidak cocok atau sudah kedaluwarsa. Muat ulang halaman lalu coba lagi.",
        );
    }

    let permissions: Vec<String> = pairs
        .into_iter()
        .filter(|(key, _)| key == "permissions")
        .map(|(_, value)| value)
        .collect();

    let caller = match caller_of(&state, &session).await {
        Ok(caller) => caller,
        Err(response) => return *response,
    };

    let Some(role_id) = Uuid::parse_str(&id).ok() else {
        return forbidden("Role tidak ditemukan di app ini.");
    };

    // Role app lain dianggap tidak ada; role sistem ditolak guard domain.
    let role = match domain_rbac::role_for_app(&state, caller.app.id, role_id).await {
        Ok(role) => role,
        Err(AppError::NotFound) => return forbidden("Role tidak ditemukan di app ini."),
        Err(err) => return err.into_response(),
    };

    if let Err(err) = domain_rbac::ensure_role_mutable(&role) {
        return err.into_response();
    }

    if let Err(err) = domain_rbac::ensure_can_grant(&caller, &permissions) {
        return err.into_response();
    }

    // Key asing diabaikan lapisan db; guard di atas sudah menolak yang di luar
    // scope pemanggil, jadi tidak ada jalur menaikkan hak akses lewat sini.
    if let Err(err) = db_rbac::set_role_permissions(&state.pool, role.id, &permissions).await {
        return AppError::from(err).into_response();
    }

    Redirect::to("/console/rbac?ok=izin-role-tersimpan").into_response()
}

/// Susun matriks dari katalog permission, daftar role, dan izin terpasang.
async fn matrix_data(state: &AppState, viewer: &Viewer) -> Result<MatrixData, AppError> {
    let app = db_apps::by_slug(&state.pool, CORE_APP)
        .await?
        .ok_or(AppError::Internal)?;

    let permissions = sqlx::query!(
        r#"
        SELECT key, name, description
        FROM permissions
        WHERE app_id = $1
        ORDER BY key
        "#,
        app.id,
    )
    .fetch_all(&state.pool)
    .await?;

    let roles = sqlx::query!(
        r#"
        SELECT id, key, name, is_system
        FROM roles
        WHERE app_id = $1
        ORDER BY is_system DESC, key
        "#,
        app.id,
    )
    .fetch_all(&state.pool)
    .await?;

    let granted = sqlx::query!(
        r#"
        SELECT rp.role_id, p.key
        FROM role_permissions rp
        JOIN permissions p ON p.id = rp.permission_id
        JOIN roles r       ON r.id = rp.role_id
        WHERE r.app_id = $1
        "#,
        app.id,
    )
    .fetch_all(&state.pool)
    .await?;

    let mut by_role: HashMap<Uuid, HashSet<String>> = HashMap::new();
    for row in granted {
        by_role.entry(row.role_id).or_default().insert(row.key);
    }

    let scope: HashSet<&str> = viewer.scope.iter().map(String::as_str).collect();
    let superadmin = viewer.is_superadmin();

    let mut rows = Vec::with_capacity(permissions.len());
    for permission in &permissions {
        let mut cells = Vec::with_capacity(roles.len());
        for role in &roles {
            let checked = by_role
                .get(&role.id)
                .is_some_and(|keys| keys.contains(&permission.key));

            // Role sistem beku untuk semua orang; sel lain hanya dinonaktifkan
            // kalau pemanggil memang tidak memegang permission itu.
            let (disabled, title) = if role.is_system {
                (true, String::from("Role sistem tidak bisa diubah."))
            } else if !superadmin && !scope.contains(permission.key.as_str()) {
                (true, String::from("Di luar izin Anda."))
            } else {
                (false, String::new())
            };

            let slug: String = permission
                .key
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect();

            cells.push(MatrixCell {
                input_id: format!("perm-{}-{slug}", role.id),
                name: format!("perm_{}", role.id),
                value: permission.key.clone(),
                checked,
                disabled,
                title,
                label: format!("{} untuk role {}", permission.key, role.name),
            });
        }

        rows.push(MatrixRow {
            key: permission.key.clone(),
            description: describe(&permission.key, &permission.description),
            cells,
        });
    }

    let any_permission = !rows.is_empty();

    Ok(MatrixData {
        rows,
        roles: roles
            .into_iter()
            .map(|role| MatrixRole {
                id: role.id.to_string(),
                key: role.key,
                name: role.name,
                is_system: role.is_system,
            })
            .collect(),
        can_write: viewer.can("role:write"),
        any_permission,
    })
}

/// Deskripsi singkat: pakai kolom database kalau terisi, kalau tidak pakai
/// kalimat pendek dari katalog registry supaya matriks tidak berisi key telanjang.
fn describe(key: &str, from_db: &str) -> String {
    if !from_db.trim().is_empty() {
        return from_db.to_string();
    }

    let text = match key {
        "auth:me" => "membaca identitas pemanggil sendiri",
        "role:read" => "membaca role dan katalog izin",
        "role:write" => "mengubah role dan izin",
        "user:read" => "membaca daftar pengguna",
        "user:write" => "membuat dan mengubah pengguna",
        "app:read" => "membaca daftar aplikasi",
        "app:write" => "membuat aplikasi dan merotasi secret",
        "audit:read" => "membaca jejak audit",
        _ => "izin dari registry route",
    };

    text.to_string()
}

fn notice(query: &NoticeQuery) -> Option<Notice> {
    if query.ok.trim().is_empty() {
        return None;
    }

    let text = match query.ok.as_str() {
        "izin-role-tersimpan" => "Izin role berhasil disimpan.",
        other => other,
    };

    Some(Notice {
        kind: "success",
        text: text.to_string(),
    })
}

/// Identitas pemilik sesi untuk shell console.
async fn viewer(state: &AppState, session: &ConsoleSession) -> Result<Viewer, Box<Response>> {
    let Ok(id) = Uuid::parse_str(&session.claims.sub) else {
        return Err(Box::new(Redirect::to("/console/login").into_response()));
    };

    match users::detail(&state.pool, id).await {
        Ok(Some(user)) => Ok(Viewer {
            name: user.display_name,
            email: user.email,
            roles: session.claims.role.clone(),
            scope: session.claims.scope.clone(),
        }),
        Ok(None) => Err(Box::new(Redirect::to("/console/login").into_response())),
        Err(err) => {
            tracing::error!(error = %err, "gagal membaca user pemilik sesi console");
            Err(Box::new(AppError::Internal.into_response()))
        }
    }
}

/// Bungkus klaim sesi jadi `AuthUser` supaya guard domain dipakai apa adanya.
///
/// Token console selalu ber-aud `core`, jadi app-nya diambil dari slug, bukan
/// dari parameter request.
async fn caller_of(state: &AppState, session: &ConsoleSession) -> Result<AuthUser, Box<Response>> {
    match db_apps::by_slug(&state.pool, CORE_APP).await {
        Ok(Some(app)) => Ok(AuthUser {
            claims: session.claims.clone(),
            app,
        }),
        Ok(None) => {
            tracing::error!("app core tidak ada; sesi console tidak bisa dipetakan");
            Err(Box::new(AppError::Internal.into_response()))
        }
        Err(err) => {
            tracing::error!(error = %err, "gagal membaca app core");
            Err(Box::new(AppError::Internal.into_response()))
        }
    }
}

/// Render halaman lalu pastikan cookie CSRF ada di browser.
fn with_csrf<T: Template>(page: T, jar: CookieJar, token: String, state: &AppState) -> Response {
    match page.render() {
        Ok(body) => (
            jar.add(csrf::cookie(token, state.config.is_prod())),
            axum::response::Html(body),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "gagal merender matriks rbac");
            AppError::Internal.into_response()
        }
    }
}

/// 403 dengan halaman error yang bisa dibaca manusia.
fn forbidden(message: &str) -> Response {
    let page = ErrorPage {
        title: "Tidak diizinkan",
        message: message.to_string(),
    };

    match page.render() {
        Ok(body) => (StatusCode::FORBIDDEN, axum::response::Html(body)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "gagal merender halaman error rbac");
            AppError::Internal.into_response()
        }
    }
}
