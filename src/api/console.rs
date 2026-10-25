//! Penyajian aset statis console dari dalam binary.
//!
//! `rust-embed` menanamkan seluruh isi `assets/` saat compile, jadi image
//! distroless cukup berisi satu berkas executable. Tidak ada path di disk yang
//! bisa hilang saat deploy dan tidak ada CDN yang harus dijangkau.
//!
//! CompressionLayer dipasang khusus di router ini: hanya aset yang punya ukuran
//! besar, dan kompresi pada respons form/redirect hanya menambah kerja.
//!
//! Predikatnya sengaja tidak memakai default tower-http: default itu mengompres
//! semua isi yang belum terkompresi menurut `Content-Type`, termasuk `font/woff2`.
//! Font WOFF2 sudah dimampatkan di dalam formatnya sendiri (Brotli per tabel),
//! jadi meng-gzip-nya hanya membuang CPU dan bisa menghasilkan byte lebih besar
//! daripada berkas aslinya. Yang dikompres hanya tipe teks.

use axum::Router;
use axum::extract::Path;
use axum::http::{Extensions, HeaderMap, StatusCode, Version, header};
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
    Router::new().route("/assets/{*path}", get(file)).layer(
        CompressionLayer::new().compress_when(
            compressible as fn(StatusCode, Version, &HeaderMap, &Extensions) -> bool,
        ),
    )
}

/// Apakah respons ini layak dikompres?
///
/// Hanya tipe teks yang lolos: CSS, JS, HTML, JSON, SVG, dan teks biasa. Aset
/// biner yang sudah termampatkan (woff2, woff, png, ico, webp) dilewati supaya
/// byte yang dikirim tidak justru membesar.
fn compressible(
    status: StatusCode,
    _version: Version,
    headers: &HeaderMap,
    _extensions: &Extensions,
) -> bool {
    if !status.is_success() && status != StatusCode::NOT_FOUND {
        return false;
    }

    let Some(value) = headers.get(header::CONTENT_TYPE) else {
        return false;
    };
    let Ok(content_type) = value.to_str() else {
        return false;
    };

    // Parameter seperti `; charset=utf-8` tidak mengubah keputusan.
    let base = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    matches!(
        base.as_str(),
        "text/css"
            | "text/javascript"
            | "text/html"
            | "text/plain"
            | "text/markdown"
            | "application/json"
            | "image/svg+xml"
    )
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
