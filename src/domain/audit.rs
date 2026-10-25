//! Pencatatan jejak audit: satu pintu untuk middleware dan handler.
//!
//! Dua sifat yang dijaga di sini. Pertama, penulisan tidak menunggu respons:
//! event dijalankan sebagai task terpisah, jadi request tidak pernah tertahan
//! oleh audit. Kedua, kegagalan menulis hanya jadi `tracing::warn!` — audit
//! yang rusak tidak boleh membuat pengguna gagal masuk atau gagal menyimpan
//! data.
//!
//! Isi event tidak pernah memuat password, secret, token, atau body request.
//! Yang dicatat hanya metadata yang sudah diketahui handler sendiri.

use axum::http::{HeaderMap, header};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::jwt::Claims;
use crate::middleware::ratelimit::client_ip;

pub use crate::db::audit::ActorType;
use crate::db::audit::NewEvent;

/// Batas panjang user-agent yang disimpan; header bisa sepanjang apa saja.
const MAX_USER_AGENT: usize = 512;

/// Nama header yang dipasang `SetRequestIdLayer` di `startup`.
const REQUEST_ID: &str = "x-request-id";

/// Bahan satu event audit dalam bentuk milik sendiri.
///
/// Dipakai builder supaya pemanggil hanya menyebut hal yang benar-benar
/// diketahuinya; sisanya tetap nilai kosong yang jujur, bukan karangan.
#[derive(Debug, Clone)]
pub struct Event {
    pub app_id: Option<Uuid>,
    pub app_slug: String,
    pub actor_type: ActorType,
    pub actor_user_id: Option<Uuid>,
    pub action: String,
    pub method: String,
    pub path: String,
    pub status_code: Option<i16>,
    pub request_id: String,
    pub ip: Option<String>,
    pub user_agent: String,
    pub metadata: Value,
}

impl Event {
    /// Event minimal: app, aksi, dan jenis pelaku. Kolom lain diisi builder.
    pub fn new(app_slug: &str, action: &str, actor_type: ActorType) -> Self {
        Self {
            app_id: None,
            app_slug: app_slug.to_string(),
            actor_type,
            actor_user_id: None,
            action: action.to_string(),
            method: String::new(),
            path: String::new(),
            status_code: None,
            request_id: String::new(),
            ip: None,
            user_agent: String::new(),
            metadata: Value::Object(serde_json::Map::new()),
        }
    }

    /// Id pelaku; `None` untuk login gagal atau pelaku service.
    pub fn actor(mut self, actor_user_id: Option<Uuid>) -> Self {
        self.actor_user_id = actor_user_id;
        self
    }

    /// Id app pemilik token, kalau handler sudah mengetahuinya.
    pub fn app(mut self, app_id: Option<Uuid>) -> Self {
        self.app_id = app_id;
        self
    }

    /// Lengkapi dari request: method, path template, request id, ip, user agent.
    pub fn request(mut self, method: &str, path: &str, headers: &HeaderMap) -> Self {
        self.method = method.to_string();
        self.path = path.to_string();
        self.request_id = header_text(headers, REQUEST_ID);
        self.user_agent = header_text(headers, header::USER_AGENT.as_str())
            .chars()
            .take(MAX_USER_AGENT)
            .collect();

        let ip = client_ip(headers, None);
        self.ip = (ip != "unknown").then_some(ip);
        self
    }

    /// Timpa ip dengan alamat peer, kalau middleware tahu alamat aslinya.
    pub fn ip(mut self, ip: String) -> Self {
        self.ip = (ip != "unknown").then_some(ip);
        self
    }

    /// Status HTTP yang benar-benar dikirim ke klien.
    pub fn status(mut self, status: u16) -> Self {
        self.status_code = i16::try_from(status).ok();
        self
    }

    /// Metadata tambahan; jangan pernah memuat kredensial atau body request.
    pub fn metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Tulis satu event tanpa menahan pemanggil.
///
/// Task sengaja dilepas: respons sudah boleh dikirim sebelum baris audit
/// mendarat. Kegagalan insert hanya dicatat di log aplikasi.
pub fn record(pool: &PgPool, event: Event) {
    let pool = pool.clone();

    tokio::spawn(async move {
        let new = NewEvent {
            app_id: event.app_id,
            app_slug: &event.app_slug,
            actor_type: event.actor_type,
            actor_user_id: event.actor_user_id,
            action: &event.action,
            method: &event.method,
            path: &event.path,
            status_code: event.status_code,
            request_id: &event.request_id,
            ip: event.ip.as_deref(),
            user_agent: &event.user_agent,
            metadata: event.metadata,
        };

        if let Err(err) = crate::db::audit::insert(&pool, &new).await {
            tracing::warn!(
                error = %err,
                action = %event.action,
                "gagal menulis audit; request tetap dianggap berhasil"
            );
        }
    });
}

/// Terjemahkan klaim token menjadi jenis pelaku dan id user.
///
/// `sub` hanya jadi `actor_user_id` kalau benar-benar UUID; token service
/// memakai `client_id` di sana, jadi id-nya tetap NULL.
pub fn actor_from_claims(claims: &Claims) -> (ActorType, Option<Uuid>) {
    let actor_type = match claims.typ.as_str() {
        "user" => ActorType::User,
        "service" => ActorType::Service,
        _ => ActorType::System,
    };

    let user_id = Uuid::parse_str(&claims.sub).ok();
    (actor_type, user_id)
}

/// Nilai satu header sebagai teks; header hilang atau tidak valid jadi kosong.
fn header_text(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}
