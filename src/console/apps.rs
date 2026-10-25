//! Layar aplikasi console: daftar, cari, buat, dan rotasi secret.
//!
//! Aturan bisnis (bentuk slug, urutan pencabutan kredensial) ada di
//! `domain::apps`; handler di sini hanya mengurus bentuk request dan respons.
//!
//! Satu hal yang sengaja berbeda dari layar pengguna: `POST` yang memuat
//! `client_secret` **tidak** menjawab redirect. Secret hanya boleh muncul di
//! badan respons POST itu sendiri, jadi handler merender halaman kredensial
//! langsung sebagai jawaban, dengan `Cache-Control: no-store`. Refresh browser
//! sesudahnya mengirim GET biasa yang tidak memuat secret apa pun.

use askama::Template;
use axum::Extension;
use axum::Form;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::console::ConsoleSession;
use crate::console::helpers;
use crate::console::views::ErrorPage;
use crate::db::apps::{self, AppKind};
use crate::db::users;
use crate::domain::apps as domain_apps;
use crate::domain::apps::IssuedCredential;
use crate::error::AppError;
use crate::middleware::csrf;
use crate::state::AppState;

/// Router layar aplikasi. Route-nya terdaftar di `rbac::registry`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/console/apps", get(list).post(create))
        .route("/console/apps/rows", get(rows))
        .route("/console/apps/new", get(new_form))
        .route("/console/apps/{id}/rotate", post(rotate))
}

/// Parameter daftar/cari aplikasi.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub q: String,
}

/// Isi form pembuatan aplikasi.
#[derive(Debug, Deserialize)]
pub struct CreateForm {
    #[serde(default)]
    pub _csrf: String,
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub kind: String,
}

/// Form rotasi hanya membawa token CSRF; id app ada di path.
#[derive(Debug, Deserialize)]
pub struct RotateForm {
    #[serde(default)]
    pub _csrf: String,
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

/// Satu baris tabel aplikasi, sudah dalam bentuk yang dibaca template.
pub struct AppRowView {
    pub id: String,
    pub slug: String,
    pub name: String,
    /// `web` | `spa` | `service` | `cli`, dipakai template untuk memilih badge.
    pub kind: &'static str,
    pub is_active: bool,
    pub access_ttl_secs: i32,
    pub live_credentials: i64,
}

/// Data yang dipakai bersama halaman daftar dan fragmen barisnya.
pub struct AppsData {
    pub rows: Vec<AppRowView>,
    pub q: String,
    /// Token CSRF untuk form rotasi di dalam baris. Dibawa di data supaya
    /// fragmen HTMX tetap membawa token yang sama dengan halamannya.
    pub csrf: String,
    /// Apakah database punya app sama sekali? Membedakan "belum ada aplikasi"
    /// dari "filter tidak menemukan apa pun".
    pub any_app: bool,
    /// Menentukan tombol aksi dirender atau tidak. Ini UX saja; penegakan
    /// sebenarnya tetap di registry route.
    pub can_write: bool,
}

/// Halaman penuh daftar aplikasi.
#[derive(Template)]
#[template(path = "apps/list.html")]
pub struct AppsPage {
    pub csrf: String,
    pub user_name: String,
    pub user_email: String,
    pub roles: Vec<String>,
    pub scope: Vec<String>,
    pub data: AppsData,
}

impl AppsPage {
    pub fn can(&self, permission: &str) -> bool {
        helpers::can(&self.scope, &self.roles, permission)
    }
}

/// Fragmen `<tbody>` untuk pencarian HTMX.
#[derive(Template)]
#[template(path = "apps/rows.html")]
pub struct AppsRows {
    pub data: AppsData,
}

/// Isi form pembuatan aplikasi.
pub struct AppFormFields {
    pub slug: String,
    pub name: String,
    pub description: String,
    pub kind: &'static str,
    pub slug_error: Option<String>,
    pub general_error: Option<String>,
}

impl AppFormFields {
    fn empty() -> Self {
        Self {
            slug: String::new(),
            name: String::new(),
            description: String::new(),
            kind: "web",
            slug_error: None,
            general_error: None,
        }
    }
}

/// Modal pembuatan aplikasi (respons untuk HTMX).
#[derive(Template)]
#[template(path = "apps/form.html")]
pub struct AppFormModal {
    pub csrf: String,
    pub form: AppFormFields,
}

/// Panel kredensial yang tampil sekali setelah create/rotate.
///
/// `client_secret` hanya ada di struct ini, dan struct ini hanya dirender oleh
/// respons POST dengan `Cache-Control: no-store`.
#[derive(Template)]
#[template(path = "apps/credentials.html")]
pub struct CredentialsPage {
    pub csrf: String,
    pub user_name: String,
    pub user_email: String,
    pub roles: Vec<String>,
    pub scope: Vec<String>,
    pub app_slug: String,
    pub app_name: String,
    pub client_id: String,
    pub client_secret: String,
    /// `create` atau `rotate`; hanya mengubah kalimat pengantarnya.
    pub mode: &'static str,
}

impl CredentialsPage {
    pub fn can(&self, permission: &str) -> bool {
        helpers::can(&self.scope, &self.roles, permission)
    }
}

/// GET /console/apps — halaman penuh daftar aplikasi.
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

    let (token, _) = csrf::token(&jar);
    let data = match data_for(&state, &query.q, viewer.can("app:write"), &token).await {
        Ok(data) => data,
        Err(err) => return err.into_response(),
    };

    let page = AppsPage {
        csrf: token.clone(),
        user_name: viewer.name,
        user_email: viewer.email,
        roles: viewer.roles,
        scope: viewer.scope,
        data,
    };

    with_csrf(render(page), jar, token, &state)
}

/// GET /console/apps/rows — fragmen baris untuk pencarian HTMX.
async fn rows(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
    Query(query): Query<ListQuery>,
) -> Response {
    let viewer = match viewer(&state, &session).await {
        Ok(viewer) => viewer,
        Err(response) => return *response,
    };

    let (token, _) = csrf::token(&jar);
    let data = match data_for(&state, &query.q, viewer.can("app:write"), &token).await {
        Ok(data) => data,
        Err(err) => return err.into_response(),
    };

    render(AppsRows { data })
}

/// GET /console/apps/new — modal pembuatan aplikasi.
async fn new_form(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
) -> Response {
    if let Err(response) = viewer(&state, &session).await {
        return *response;
    }

    let (token, _) = csrf::token(&jar);
    with_csrf(
        render(AppFormModal {
            csrf: token.clone(),
            form: AppFormFields::empty(),
        }),
        jar,
        token,
        &state,
    )
}

/// POST /console/apps — buat aplikasi lalu tampilkan panel secret sekali.
async fn create(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
    Form(form): Form<CreateForm>,
) -> Response {
    if !csrf::matches(&jar, &form._csrf) {
        return csrf_rejected();
    }

    let viewer = match viewer(&state, &session).await {
        Ok(viewer) => viewer,
        Err(response) => return *response,
    };

    let Some(kind) = parse_kind(&form.kind) else {
        return form_response(
            &state,
            jar,
            &viewer,
            AppFormFields {
                slug: form.slug,
                name: form.name,
                description: form.description,
                kind: "web",
                slug_error: None,
                general_error: Some("Jenis aplikasi tidak dikenal.".to_string()),
            },
            StatusCode::BAD_REQUEST,
        );
    };

    match domain_apps::create_app(
        &state.pool,
        &state.config,
        &form.slug,
        &form.name,
        kind,
        &form.description,
    )
    .await
    {
        Ok((app, credential)) => {
            let page = CredentialsPage {
                csrf: form._csrf,
                user_name: viewer.name,
                user_email: viewer.email,
                roles: viewer.roles,
                scope: viewer.scope,
                app_slug: app.slug,
                app_name: app.name,
                client_id: credential.client_id,
                client_secret: credential.client_secret,
                mode: "create",
            };

            secret_response(page, StatusCode::CREATED)
        }
        Err(err) => {
            let (status, slug_error, general_error) = describe_error(&err);
            form_response(
                &state,
                jar,
                &viewer,
                AppFormFields {
                    slug: form.slug,
                    name: form.name,
                    description: form.description,
                    kind: kind_name(kind),
                    slug_error,
                    general_error,
                },
                status,
            )
        }
    }
}

/// POST /console/apps/{id}/rotate — cabut kredensial lama, tampilkan yang baru.
async fn rotate(
    State(state): State<AppState>,
    Extension(session): Extension<ConsoleSession>,
    jar: CookieJar,
    Path(id): Path<String>,
    Form(form): Form<RotateForm>,
) -> Response {
    if !csrf::matches(&jar, &form._csrf) {
        return csrf_rejected();
    }

    let viewer = match viewer(&state, &session).await {
        Ok(viewer) => viewer,
        Err(response) => return *response,
    };

    let Some(id) = Uuid::parse_str(&id).ok() else {
        return not_found();
    };

    let app = match apps::by_id(&state.pool, id).await {
        Ok(Some(app)) => app,
        Ok(None) => return not_found(),
        Err(err) => return AppError::from(err).into_response(),
    };

    match domain_apps::rotate_secret(&state.pool, &state.config, app.id).await {
        Ok(credential) => secret_response(
            credentials_page(&form._csrf, &viewer, &app, credential, "rotate"),
            StatusCode::OK,
        ),
        Err(err) => err.into_response(),
    }
}

/// Halaman kredensial untuk create/rotate.
fn credentials_page(
    csrf_token: &str,
    viewer: &Viewer,
    app: &apps::App,
    credential: IssuedCredential,
    mode: &'static str,
) -> CredentialsPage {
    CredentialsPage {
        csrf: csrf_token.to_string(),
        user_name: viewer.name.clone(),
        user_email: viewer.email.clone(),
        roles: viewer.roles.clone(),
        scope: viewer.scope.clone(),
        app_slug: app.slug.clone(),
        app_name: app.name.clone(),
        client_id: credential.client_id,
        client_secret: credential.client_secret,
        mode,
    }
}

/// Render panel kredensial dengan `Cache-Control: no-store`.
///
/// Header itu wajib: tanpa itu proxy atau cache browser bisa menyimpan halaman
/// berisi secret, dan "hanya tampil sekali" jadi bohong.
fn secret_response<T: Template>(page: T, status: StatusCode) -> Response {
    match page.render() {
        Ok(body) => (status, [(header::CACHE_CONTROL, "no-store")], Html(body)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "gagal merender panel kredensial");
            AppError::Internal.into_response()
        }
    }
}

/// Render modal form dengan status tertentu (dipakai saat validasi gagal).
fn form_response(
    state: &AppState,
    jar: CookieJar,
    _viewer: &Viewer,
    form: AppFormFields,
    status: StatusCode,
) -> Response {
    let (token, _) = csrf::token(&jar);
    match (AppFormModal {
        csrf: token.clone(),
        form,
    })
    .render()
    {
        Ok(body) => (
            status,
            jar.add(csrf::cookie(token, state.config.is_prod())),
            Html(body),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "gagal merender form aplikasi");
            AppError::Internal.into_response()
        }
    }
}

/// Ambil identitas pemilik sesi untuk shell console.
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

/// Satu halaman data aplikasi.
async fn data_for(
    state: &AppState,
    q: &str,
    can_write: bool,
    csrf_token: &str,
) -> Result<AppsData, AppError> {
    let rows = apps::list_rows(&state.pool, Some(q)).await?;
    let any_app = apps::count(&state.pool).await? > 0;

    Ok(AppsData {
        rows: rows.into_iter().map(row_view).collect(),
        q: q.to_string(),
        csrf: csrf_token.to_string(),
        any_app,
        can_write,
    })
}

fn row_view(row: apps::AppRow) -> AppRowView {
    AppRowView {
        id: row.id.to_string(),
        slug: row.slug,
        name: row.name,
        kind: kind_name(row.kind),
        is_active: row.is_active,
        access_ttl_secs: row.access_ttl_secs,
        live_credentials: row.live_credentials,
    }
}

/// Nama jenis yang dipakai template untuk memilih badge.
fn kind_name(kind: AppKind) -> &'static str {
    match kind {
        AppKind::Web => "web",
        AppKind::Spa => "spa",
        AppKind::Service => "service",
        AppKind::Cli => "cli",
    }
}

fn parse_kind(raw: &str) -> Option<AppKind> {
    match raw {
        "web" => Some(AppKind::Web),
        "spa" => Some(AppKind::Spa),
        "service" => Some(AppKind::Service),
        "cli" => Some(AppKind::Cli),
        _ => None,
    }
}

/// Terjemahkan kegagalan domain ke field yang tepat di form.
fn describe_error(err: &AppError) -> (StatusCode, Option<String>, Option<String>) {
    match err {
        AppError::Conflict(message) => (StatusCode::CONFLICT, Some(message.clone()), None),
        AppError::BadRequest(message) => (StatusCode::BAD_REQUEST, None, Some(message.clone())),
        AppError::Forbidden => (StatusCode::FORBIDDEN, None, None),
        AppError::Unauthorized => (StatusCode::UNAUTHORIZED, None, None),
        AppError::NotFound => (StatusCode::NOT_FOUND, None, None),
        AppError::TooManyRequests | AppError::Internal => (
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            Some("Permintaan gagal diproses. Coba lagi.".to_string()),
        ),
    }
}

fn render<T: Template>(template: T) -> Response {
    match template.render() {
        Ok(body) => Html(body).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "gagal merender template aplikasi");
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

/// 403 untuk token CSRF yang tidak cocok.
fn csrf_rejected() -> Response {
    let page = ErrorPage {
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

/// 404 untuk id yang tidak ada atau bukan UUID.
fn not_found() -> Response {
    let page = ErrorPage {
        title: "Tidak ditemukan",
        message: "Aplikasi itu tidak ada. Mungkin sudah dihapus.".to_string(),
    };

    match page.render() {
        Ok(body) => (StatusCode::NOT_FOUND, Html(body)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "gagal merender halaman 404 console");
            AppError::Internal.into_response()
        }
    }
}
