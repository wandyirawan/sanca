//! Layar audit: membaca `audit_events` dengan filter app, aktor, dan rentang
//! tanggal.
//!
//! Penulis event belum ada di phase ini (middleware audit menyusul di phase
//! hardening), jadi halaman ini sengaja punya empty state yang jujur: tabel
//! kosong bukan berarti fitur rusak, hanya belum ada yang mencatat.

use askama::Template;
use axum::Extension;
use axum::Router;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use time::OffsetDateTime;
use time::macros::format_description;
use uuid::Uuid;

use crate::console::ConsoleSession;
use crate::console::helpers;
use crate::db::apps as db_apps;
use crate::db::audit::{self, ActorType};
use crate::db::users;
use crate::error::AppError;
use crate::middleware::csrf;
use crate::state::AppState;

/// Jumlah baris default dan batas atas yang diterima dari query.
const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

/// Router layar audit. Route-nya terdaftar di `rbac::registry`.
pub fn router() -> Router<AppState> {
    Router::new().route("/console/audit", get(list))
}

/// Filter yang dibaca dari query string. Semua opsional supaya URL bersih tetap
/// berarti "50 aktivitas terbaru".
#[derive(Debug, Default, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub app_slug: String,
    #[serde(default)]
    pub actor: String,
    /// Tanggal `YYYY-MM-DD`, inklusif.
    #[serde(default)]
    pub dari: String,
    #[serde(default)]
    pub sampai: String,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

/// Satu baris tabel audit dalam bentuk yang dibaca template.
pub struct AuditRowView {
    /// Waktu dalam UTC, format ringkas dan mudah dibaca.
    pub occurred_at: String,
    pub app_slug: String,
    pub actor: String,
    pub action: String,
    pub method: String,
    pub path: String,
    pub status: String,
    pub request_id: String,
}

/// Data halaman audit.
pub struct AuditData {
    pub rows: Vec<AuditRowView>,
    pub app_slug: String,
    pub actor: String,
    pub dari: String,
    pub sampai: String,
    pub limit: i64,
    pub offset: i64,
    /// Daftar slug app untuk dropdown filter.
    pub apps: Vec<String>,
    /// Apakah filter apa pun sedang aktif? Menentukan kalimat empty state.
    pub filtered: bool,
    pub has_prev: bool,
    pub has_next: bool,
    pub prev_offset: i64,
    pub next_offset: i64,
}

impl AuditData {
    pub fn range_label(&self) -> String {
        if self.rows.is_empty() {
            return String::from("0 baris");
        }
        format!(
            "{}-{}",
            self.offset + 1,
            self.offset + self.rows.len() as i64
        )
    }
}

/// Halaman audit.
#[derive(Template)]
#[template(path = "audit/list.html")]
pub struct AuditPage {
    pub csrf: String,
    pub user_name: String,
    pub user_email: String,
    pub roles: Vec<String>,
    pub scope: Vec<String>,
    pub data: AuditData,
}

impl AuditPage {
    pub fn can(&self, permission: &str) -> bool {
        helpers::can(&self.scope, &self.roles, permission)
    }
}

/// Fragmen `<tbody>` tabel audit.
#[derive(Template)]
#[template(path = "audit/rows.html")]
pub struct AuditRows {
    pub data: AuditData,
}

/// Identitas pemilik sesi untuk shell console.
struct Viewer {
    name: String,
    email: String,
    roles: Vec<String>,
    scope: Vec<String>,
}

/// GET /console/audit — daftar event dengan filter.
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

    let data = match data_for(&state, &query).await {
        Ok(data) => data,
        Err(err) => return err.into_response(),
    };

    let (token, _) = csrf::token(&jar);
    let page = AuditPage {
        csrf: token.clone(),
        user_name: viewer.name,
        user_email: viewer.email,
        roles: viewer.roles,
        scope: viewer.scope,
        data,
    };

    match page.render() {
        Ok(body) => (
            jar.add(csrf::cookie(token, state.config.is_prod())),
            axum::response::Html(body),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "gagal merender halaman audit");
            AppError::Internal.into_response()
        }
    }
}

/// Kumpulkan baris audit sesuai filter query.
async fn data_for(state: &AppState, query: &ListQuery) -> Result<AuditData, AppError> {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = query.offset.unwrap_or(0).max(0);

    let app_slug = query.app_slug.trim();
    let actor_text = query.actor.trim();
    let actor_pattern = (!actor_text.is_empty()).then(|| format!("%{actor_text}%"));

    let from = parse_day(&query.dari)?;
    // Batas atas eksklusif: satu hari penuh tetap ikut walau jamnya 23:59.
    let until = parse_day(&query.sampai)?.map(|value| value + time::Duration::days(1));

    let filter = audit::Filter {
        app_slug: (!app_slug.is_empty()).then_some(app_slug),
        actor: actor_pattern.as_deref(),
        from,
        until,
        // Ambil satu baris lebih banyak untuk mengetahui apakah masih ada
        // halaman berikutnya tanpa query hitung terpisah.
        limit: limit + 1,
        offset,
    };

    let mut rows = audit::list_filtered(&state.pool, &filter).await?;
    let has_next = rows.len() as i64 > limit;
    rows.truncate(limit as usize);

    let apps = db_apps::list_rows(&state.pool, None)
        .await?
        .into_iter()
        .map(|app| app.slug)
        .collect();

    let filtered = !app_slug.is_empty()
        || !actor_text.is_empty()
        || !query.dari.trim().is_empty()
        || !query.sampai.trim().is_empty();

    Ok(AuditData {
        rows: rows.into_iter().map(row_view).collect(),
        app_slug: app_slug.to_string(),
        actor: actor_text.to_string(),
        dari: query.dari.trim().to_string(),
        sampai: query.sampai.trim().to_string(),
        limit,
        offset,
        apps,
        filtered,
        has_prev: offset > 0,
        has_next,
        prev_offset: (offset - limit).max(0),
        next_offset: offset + limit,
    })
}

/// Ubah `YYYY-MM-DD` jadi tengah malam UTC. String kosong berarti tanpa batas.
fn parse_day(value: &str) -> Result<Option<OffsetDateTime>, AppError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }

    let format = format_description!("[year]-[month]-[day]");
    match time::Date::parse(value, format) {
        Ok(date) => Ok(Some(date.midnight().assume_utc())),
        Err(_) => Err(AppError::BadRequest(format!(
            "Tanggal \"{value}\" tidak dikenali; gunakan format YYYY-MM-DD."
        ))),
    }
}

fn row_view(row: audit::AuditRow) -> AuditRowView {
    let actor = match (row.actor_user_id, row.actor_type) {
        (Some(id), _) => id.to_string(),
        (None, ActorType::System) => "sistem".to_string(),
        (None, ActorType::Service) => "service".to_string(),
        (None, ActorType::User) => "tidak diketahui".to_string(),
    };

    AuditRowView {
        occurred_at: format_stamp(row.occurred_at),
        app_slug: row.app_slug,
        actor,
        action: row.action,
        method: row.method,
        path: row.path,
        status: row
            .status_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "—".to_string()),
        request_id: row.request_id,
    }
}

/// `2026-10-25 14:03:22 UTC` — urutan yang sama dengan penyortiran tabel.
fn format_stamp(value: OffsetDateTime) -> String {
    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    match value.format(format) {
        Ok(text) => format!("{text} UTC"),
        Err(_) => value.to_string(),
    }
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
