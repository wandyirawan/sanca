//! Penyajian aset statis console dari dalam binary.
//!
//! `rust-embed` menanamkan seluruh isi `assets/` saat compile, jadi image
//! distroless cukup berisi satu berkas executable. Tidak ada path di disk yang
//! bisa hilang saat deploy dan tidak ada CDN yang harus dijangkau.
//!
//! CompressionLayer dipasang khusus di router ini: hanya aset yang punya ukuran
//! besar, dan kompresi pada respons form/redirect hanya menambah kerja.

use axum::Router;
use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rust_embed::RustEmbed;
use tower_http::compression::CompressionLayer;

use crate::state::AppState;

/// Aset yang di-vendor (daisyUI, htmx, font) jarang berubah: boleh di-cache lama.
const VENDOR_CACHE: &str = "public, max-age=31536000, immutable";

/// `app.css` ditulis tangan dan ikut berubah saat pengembangan: cache pendek.
const APP_CACHE: &str = "public, max-age=60";

#[derive(RustEmbed)]
#[folder = "assets"]
struct Assets;

/// Router aset. Path-nya wildcard karena isi `assets/` boleh bertambah tanpa
/// menyentuh kode; registry mendaftarkannya sebagai route publik.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/assets/{*path}", get(file))
        .layer(CompressionLayer::new())
}

/// Kirim satu berkas aset yang sudah tertanam.
async fn file(Path(path): Path<String>) -> Response {
    let Some(asset) = Assets::get(&path) else {
        return (StatusCode::NOT_FOUND, "aset tidak ditemukan").into_response();
    };

    let cache = if path.starts_with("vendor/") {
        VENDOR_CACHE
    } else {
        APP_CACHE
    };

    (
        [
            (header::CONTENT_TYPE, content_type(&path)),
            (header::CACHE_CONTROL, cache),
        ],
        asset.data,
    )
        .into_response()
}

/// Tipe konten berdasarkan ekstensi. Hanya jenis yang benar-benar ada di
/// `assets/` yang dipetakan supaya tabelnya tidak menjadi daftar spekulatif.
fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        Some("md") => "text/markdown; charset=utf-8",
        _ => "application/octet-stream",
    }
}
