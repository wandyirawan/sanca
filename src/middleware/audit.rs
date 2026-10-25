//! Middleware audit HTTP: satu baris per request untuk route yang penting.
//!
//! Posisinya sengaja di luar `rbac::enforce` tetapi di dalam `session_gate`.
//! Di luar enforce, karena penolakan 403 justru peristiwa yang harus tercatat
//! dan enforce tidak memanggil handler saat menolak. Di dalam session_gate,
//! karena gate itulah yang mengubah cookie console menjadi header
//! `Authorization`, jadi identitas pelaku console ikut terbaca.
//!
//! Identitas diambil dari token yang sudah lolos verifikasi di header request:
//! `verify_access` hanya membaca tanda tangan (tanpa query database), jadi
//! audit tidak menambah beban database sama sekali. Token tidak sah berarti
//! request memang tidak terautentikasi, dan itu tidak dicatat.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;

use crate::auth::jwt::verify_access;
use crate::domain::audit::{self, Event};
use crate::middleware::ratelimit::client_ip;
use crate::rbac::registry;
use crate::state::AppState;

/// Catat satu event untuk route yang `audit_action`-nya terisi.
///
/// Route tanpa aksi audit (health, aset statis, JWKS) langsung diteruskan tanpa
/// biaya apa pun. Penulisan event tidak menahan respons: `audit::record`
/// melepasnya sebagai task terpisah.
pub async fn audit(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(path) = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
    else {
        return next.run(request).await;
    };

    let method = request.method().clone();

    let Some(route) = registry::find(&method, &path) else {
        return next.run(request).await;
    };
    let Some(action) = route.audit_action else {
        return next.run(request).await;
    };
    let Some(slug) = route.scope.app_slug() else {
        return next.run(request).await;
    };

    let headers = request.headers().clone();
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = client_ip(&headers, peer);

    // Respons tetap dikirim apa pun hasil audit; yang di bawah ini hanya
    // membaca status dan identitas, tidak mengubah body.
    let response = next.run(request).await;

    let Some(claims) = bearer_token(&headers)
        .and_then(|token| verify_access(&state.config, &state.signing, token, slug).ok())
    else {
        return response;
    };

    let (actor_type, actor_user_id) = audit::actor_from_claims(&claims);

    let event = Event::new(slug, action, actor_type)
        .actor(actor_user_id)
        .app(uuid_of(&claims.azp))
        .request(method.as_str(), &path, &headers)
        .ip(ip)
        .status(response.status().as_u16());

    audit::record(&state.pool, event);
    response
}

/// Token dari header `Authorization`, kalau ada dan berbentuk Bearer.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// Klaim `azp` berisi id app; yang tidak bisa diparse jadi `None`, bukan panic.
fn uuid_of(value: &str) -> Option<uuid::Uuid> {
    uuid::Uuid::parse_str(value).ok()
}
