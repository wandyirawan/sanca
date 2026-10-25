//! Layar pengguna console: daftar, cari, detail, dan form create/edit.
//!
//! Handler di sini hanya mengurus bentuk request dan bentuk respons. Aturan
//! bisnis (siapa boleh membuat superadmin, kapan token dicabut, email duplikat)
//! tetap di `domain::users` — layar ini memanggil fungsi yang sama dengan API,
//! jadi tidak ada aturan kedua yang bisa menyimpang.

use askama::Template;
use axum::Extension;
use axum::Form;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::extractor::AuthUser;
use crate::console::ConsoleSession;
use crate::console::helpers;
use crate::console::views::{
    Notice, UserDetailFields, UserDetailModal, UserFormFields, UserFormModal, UserFormPage,
    UserRowView, UsersData, UsersPage, UsersRows,
};
use crate::db::rbac;
use crate::db::users::{self, UserStatus};
use crate::domain::users as domain_users;
use crate::domain::users::{NewUser, UserChanges};
use crate::error::AppError;
use crate::middleware::csrf;
use crate::state::AppState;

/// Jumlah baris per halaman. Sama dengan default API supaya dua jalur tidak
/// memberi kesan katalog yang berbeda.
const PAGE_SIZE: i64 = 20;

/// Router layar pengguna. Route-nya terdaftar di `rbac::registry`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/console/users", get(list).post(create))
        .route("/console/users/rows", get(rows))
        .route("/console/users/new", get(new_form))
        .route("/console/users/{id}", get(detail).post(update))
        .route("/console/users/{id}/edit", get(edit_form))
}

/// Parameter daftar/cari. `limit` sengaja tidak dari klien: satu halaman selalu
/// `PAGE_SIZE` baris supaya pager dan label "x-y dari N" tidak bisa menipu.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub offset: i64,
    /// Kode hasil aksi dari redirect sebelumnya (`?ok=created`).
    #[serde(default)]
    pub ok: Option<String>,
    /// Kode kegagalan dari redirect sebelumnya (`?err=email_taken`).
    #[serde(default)]
    pub err: Option<String>,
}

/// Isi form pembuatan user. `is_superadmin` tidak pernah dibaca dari form:
/// layar ini sengaja hanya membuat user biasa, promosi superadmin lewat API.
#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    pub _csrf: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub password: String,
}

/// Isi form perubahan user. `password` kosong berarti tidak diubah.
#[derive(Debug, Deserialize)]
pub struct UpdateForm {
    #[serde(default)]
    pub _csrf: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub password: String,
}

/// Identitas pemilik sesi untuk shell console (layout + partial nav).
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
}

/// GET /console/users — halaman penuh daftar user.
async fn list(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
    Query(query): Query<ListQuery>,
) -> Response {
    let viewer = match viewer(&state, &session).await {
        Ok(viewer) => viewer,
        Err(response) => return *response,
    };

    let offset = query.offset.max(0);
    let can_write = viewer.can("user:write");
    let data = match data_for(&state, &query.q, offset, can_write).await {
        Ok(data) => data,
        Err(err) => return err.into_response(),
    };

    let (token, _) = csrf::token(&jar);
    let page = UsersPage {
        csrf: token.clone(),
        user_name: viewer.name,
        user_email: viewer.email,
        roles: viewer.roles,
        scope: viewer.scope,
        data,
        notice: notice(query.ok.as_deref(), query.err.as_deref()),
    };

    with_csrf(render(page), jar, token, &state)
}

/// GET /console/users/rows — fragmen baris untuk pencarian dan paging HTMX.
async fn rows(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    Query(query): Query<ListQuery>,
) -> Response {
    let viewer = match viewer(&state, &session).await {
        Ok(viewer) => viewer,
        Err(response) => return *response,
    };

    let offset = query.offset.max(0);
    let can_write = viewer.can("user:write");
    let data = match data_for(&state, &query.q, offset, can_write).await {
        Ok(data) => data,
        Err(err) => return err.into_response(),
    };

    render(UsersRows { data })
}

/// GET /console/users/new — form pembuatan; modal untuk HTMX, halaman untuk
/// permintaan biasa (jalur tanpa JavaScript).
async fn new_form(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Response {
    let viewer = match viewer(&state, &session).await {
        Ok(viewer) => viewer,
        Err(response) => return *response,
    };

    form_response(
        &state,
        jar,
        &headers,
        &viewer,
        UserFormFields {
            mode: "create",
            action: "/console/users".to_string(),
            email: String::new(),
            display_name: String::new(),
            status: "active",
            email_error: None,
            name_error: None,
            password_error: None,
            general_error: None,
        },
    )
}

/// GET /console/users/{id}/edit — form perubahan user yang sudah ada.
async fn edit_form(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let viewer = match viewer(&state, &session).await {
        Ok(viewer) => viewer,
        Err(response) => return *response,
    };

    let Some(id) = parse_id(&id) else {
        return not_found();
    };

    let Ok(Some(user)) = users::detail(&state.pool, id).await else {
        return not_found();
    };

    form_response(
        &state,
        jar,
        &headers,
        &viewer,
        UserFormFields {
            mode: "edit",
            action: format!("/console/users/{id}"),
            email: user.email,
            display_name: user.display_name,
            status: status_name(user.status),
            email_error: None,
            name_error: None,
            password_error: None,
            general_error: None,
        },
    )
}

/// GET /console/users/{id} — modal detail berisi atribut dan role user.
async fn detail(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(id) = parse_id(&id) else {
        return not_found();
    };

    let Ok(Some(user)) = users::detail(&state.pool, id).await else {
        return not_found();
    };

    let role_names = rbac::roles_of_user(&state.pool, id)
        .await
        .map(|roles| roles.into_iter().map(|role| role.name).collect::<Vec<_>>())
        .unwrap_or_default();

    render(UserDetailModal {
        detail: UserDetailFields {
            email: user.email,
            display_name: user.display_name,
            status: status_name(user.status),
            is_superadmin: user.is_superadmin,
            token_version: user.token_version,
            created_at: format_time(user.created_at),
            role_names,
        },
    })
}

/// POST /console/users — buat user lewat form biasa lalu kembali ke daftar.
async fn create(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
    headers: HeaderMap,
    caller: AuthUser,
    Form(form): Form<CreateForm>,
) -> Response {
    if !csrf::matches(&jar, &form._csrf) {
        return csrf_rejected();
    }

    let viewer = match viewer(&state, &session).await {
        Ok(viewer) => viewer,
        Err(response) => return *response,
    };

    let input = NewUser {
        email: form.email.clone(),
        password: form.password.clone(),
        display_name: form.display_name.clone(),
        is_superadmin: false,
    };

    match domain_users::create_user(&state, &caller, input).await {
        Ok(_) => redirect_with(jar, "/console/users?ok=created"),
        Err(err) => {
            let (status, email_error, password_error, general_error) = describe_error(&err);
            let response = form_response(
                &state,
                jar,
                &headers,
                &viewer,
                UserFormFields {
                    mode: "create",
                    action: "/console/users".to_string(),
                    email: form.email,
                    display_name: form.display_name,
                    status: "active",
                    email_error,
                    name_error: None,
                    password_error,
                    general_error,
                },
            );
            (status, response).into_response()
        }
    }
}

/// POST /console/users/{id} — ubah profil, status, dan/atau password.
async fn update(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
    headers: HeaderMap,
    caller: AuthUser,
    Path(id): Path<String>,
    Form(form): Form<UpdateForm>,
) -> Response {
    if !csrf::matches(&jar, &form._csrf) {
        return csrf_rejected();
    }

    let viewer = match viewer(&state, &session).await {
        Ok(viewer) => viewer,
        Err(response) => return *response,
    };

    let Some(id) = parse_id(&id) else {
        return not_found();
    };

    let status = match form.status.as_str() {
        "active" => Some(UserStatus::Active),
        "disabled" => Some(UserStatus::Disabled),
        "pending" => Some(UserStatus::Pending),
        other => {
            return edit_form_body(
                &state,
                jar,
                &headers,
                &viewer,
                id,
                None,
                Some(format!("Status {other:?} tidak dikenal.")),
            )
            .await;
        }
    };

    // Password kosong berarti "jangan sentuh", bukan "kosongkan".
    let password = if form.password.is_empty() {
        None
    } else {
        Some(form.password)
    };

    let changes = UserChanges {
        display_name: Some(form.display_name),
        status,
        password,
    };

    match domain_users::update_user(&state, &caller, id, changes).await {
        Ok(_) => redirect_with(jar, "/console/users?ok=updated"),
        Err(err) => {
            let (status, _, password_error, general_error) = describe_error(&err);
            let response = edit_form_body(
                &state,
                jar,
                &headers,
                &viewer,
                id,
                password_error,
                general_error,
            )
            .await;
            (status, response).into_response()
        }
    }
}

/// Ambil identitas pemilik sesi untuk shell console.
///
/// Gagal baca database bukan alasan menampilkan halaman setengah jadi: pengguna
/// dikirim ke login seperti sesi yang tidak sah.
async fn viewer(state: &AppState, session: &ConsoleSession) -> Result<Viewer, Box<Response>> {
    let Some(id) = parse_id(&session.claims.sub) else {
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

/// Satu halaman data user: baris, filter, dan angka untuk pager.
async fn data_for(
    state: &AppState,
    q: &str,
    offset: i64,
    can_write: bool,
) -> Result<UsersData, AppError> {
    let filter = Some(q);
    let rows = users::list_rows(&state.pool, filter, PAGE_SIZE, offset).await?;
    let total = users::count(&state.pool, filter).await?;

    // Bedakan "katalog kosong" dari "filter tidak menemukan apa pun". Query
    // kedua hanya dijalankan saat halaman kosong, jadi tidak membebani kasus
    // normal.
    let any_user = if total > 0 {
        true
    } else if q.trim().is_empty() {
        false
    } else {
        users::count(&state.pool, None).await? > 0
    };

    Ok(UsersData {
        rows: rows.into_iter().map(row_view).collect(),
        q: q.to_string(),
        limit: PAGE_SIZE,
        offset,
        total,
        any_user,
        can_write,
    })
}

/// Ubah baris database menjadi baris tampilan.
fn row_view(row: users::UserRow) -> UserRowView {
    UserRowView {
        id: row.id.to_string(),
        email: row.email,
        display_name: row.display_name,
        status: status_name(row.status),
        is_superadmin: row.is_superadmin,
        role_count: row.role_count,
    }
}

/// Nama status yang dipakai template untuk memilih badge.
fn status_name(status: UserStatus) -> &'static str {
    match status {
        UserStatus::Active => "active",
        UserStatus::Disabled => "disabled",
        UserStatus::Pending => "pending",
    }
}

/// Waktu dibuat dalam bentuk yang enak dibaca manusia, tanpa dependensi baru.
fn format_time(value: time::OffsetDateTime) -> String {
    let format = time::macros::format_description!("[year]-[month]-[day] [hour]:[minute] UTC");
    value
        .to_offset(time::UtcOffset::UTC)
        .format(&format)
        .unwrap_or_else(|_| value.to_string())
}

/// Render form: modal kalau permintaan datang dari HTMX, halaman penuh kalau
/// tidak. Satu handler melayani dua jalur supaya form tetap berfungsi tanpa JS.
fn form_response(
    state: &AppState,
    jar: CookieJar,
    headers: &HeaderMap,
    viewer: &Viewer,
    form: UserFormFields,
) -> Response {
    let (token, _) = csrf::token(&jar);

    if is_htmx(headers) {
        return with_csrf(
            render(UserFormModal {
                csrf: token.clone(),
                form,
            }),
            jar,
            token,
            state,
        );
    }

    let page = UserFormPage {
        csrf: token.clone(),
        user_name: viewer.name.clone(),
        user_email: viewer.email.clone(),
        roles: viewer.roles.clone(),
        scope: viewer.scope.clone(),
        form,
    };

    with_csrf(render(page), jar, token, state)
}

/// Form edit yang dirender ulang setelah validasi gagal, lengkap dengan nilai
/// terbaru dari database.
async fn edit_form_body(
    state: &AppState,
    jar: CookieJar,
    headers: &HeaderMap,
    viewer: &Viewer,
    id: Uuid,
    password_error: Option<String>,
    general_error: Option<String>,
) -> Response {
    let Ok(Some(user)) = users::detail(&state.pool, id).await else {
        return not_found();
    };

    form_response(
        state,
        jar,
        headers,
        viewer,
        UserFormFields {
            mode: "edit",
            action: format!("/console/users/{id}"),
            email: user.email,
            display_name: user.display_name,
            status: status_name(user.status),
            email_error: None,
            name_error: None,
            password_error,
            general_error,
        },
    )
}

/// Apakah permintaan ini datang dari HTMX? Header-nya yang dipakai, bukan
/// parameter tambahan, supaya URL tetap bersih dan bisa dibuka langsung.
fn is_htmx(headers: &HeaderMap) -> bool {
    headers
        .get("HX-Request")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("true"))
}

/// Terjemahkan kegagalan domain menjadi pesan di field yang tepat.
///
/// Email duplikat dan password terlalu pendek punya field sendiri; sisanya
/// masuk ke kotak error umum supaya pengguna tetap tahu apa yang salah.
fn describe_error(err: &AppError) -> (StatusCode, Option<String>, Option<String>, Option<String>) {
    match err {
        AppError::Conflict(message) => (StatusCode::CONFLICT, Some(message.clone()), None, None),
        AppError::BadRequest(message) if message.starts_with("password") => {
            (StatusCode::BAD_REQUEST, None, Some(message.clone()), None)
        }
        AppError::BadRequest(message) => {
            (StatusCode::BAD_REQUEST, None, None, Some(message.clone()))
        }
        AppError::Forbidden => (StatusCode::FORBIDDEN, None, None, None),
        AppError::Unauthorized => (StatusCode::UNAUTHORIZED, None, None, None),
        AppError::NotFound => (StatusCode::NOT_FOUND, None, None, None),
        AppError::TooManyRequests | AppError::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            None,
            Some("Permintaan gagal diproses. Coba lagi.".to_string()),
        ),
    }
}

/// 303 setelah aksi berhasil; pesan hasilnya dibawa lewat query `?ok=`.
fn redirect_with(jar: CookieJar, location: &str) -> Response {
    (jar, Redirect::to(location)).into_response()
}

/// Pesan notifikasi dari query string hasil redirect.
///
/// Cara ini dipilih (bukan `HX-Trigger`) karena tetap bekerja saat HTMX mati:
/// redirect biasa pun membawa pesan yang sama.
fn notice(ok: Option<&str>, err: Option<&str>) -> Option<Notice> {
    match (ok, err) {
        (Some("created"), _) => Some(Notice {
            kind: "success",
            text: "Pengguna baru dibuat.".to_string(),
        }),
        (Some("updated"), _) => Some(Notice {
            kind: "success",
            text: "Perubahan pengguna disimpan.".to_string(),
        }),
        (_, Some("email_taken")) => Some(Notice {
            kind: "error",
            text: "Email itu sudah dipakai pengguna lain.".to_string(),
        }),
        _ => None,
    }
}

/// Render template jadi HTML; gagal render = 500, bukan halaman setengah jadi.
fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "gagal merender template pengguna");
            AppError::Internal.into_response()
        }
    }
}

/// Pasang cookie CSRF pada respons kalau tokennya baru dibuat.
fn with_csrf(response: Response, jar: CookieJar, token: String, state: &AppState) -> Response {
    (
        jar.add(csrf::cookie(token, state.config.is_prod())),
        response,
    )
        .into_response()
}

/// 403 untuk token CSRF yang tidak cocok, memakai halaman error console.
fn csrf_rejected() -> Response {
    let page = crate::console::views::ErrorPage {
        title: "Permintaan ditolak",
        message: "Token keamanan form tidak cocok atau sudah kedaluwarsa. \
                  Muat ulang halaman lalu coba lagi."
            .to_string(),
    };

    match page.render() {
        Ok(body) => (StatusCode::FORBIDDEN, Html(body)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "gagal merender halaman error console");
            AppError::Internal.into_response()
        }
    }
}

/// 404 sederhana untuk id yang tidak ada atau bukan UUID.
fn not_found() -> Response {
    let page = crate::console::views::ErrorPage {
        title: "Tidak ditemukan",
        message: "Pengguna itu tidak ada. Mungkin sudah dihapus.".to_string(),
    };

    match page.render() {
        Ok(body) => (StatusCode::NOT_FOUND, Html(body)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "gagal merender halaman 404 console");
            AppError::Internal.into_response()
        }
    }
}

/// UUID dari path; `None` kalau bentuknya tidak sah.
fn parse_id(raw: &str) -> Option<Uuid> {
    Uuid::parse_str(raw).ok()
}
