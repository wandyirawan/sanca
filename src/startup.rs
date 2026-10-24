use std::io::{Read, Write};
use std::net::TcpStream;

use axum::Router;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

use crate::api;
use crate::cli::Cli;
use crate::config::Config;

/// Merakit `Router` aplikasi lengkap dengan layer observability.
///
/// Dipakai oleh `main` dan oleh test integrasi supaya wiring tidak diduplikasi.
pub fn build_app() -> Router {
    // Urutan layer: yang ditambahkan paling akhir = paling luar. Jadi SetRequestId
    // jalan lebih dulu (membuat id dan menaruhnya di header request), baru TraceLayer
    // membuat span yang sudah memuat id itu, lalu PropagateRequestId menyalinnya ke
    // respons. Tanpa Propagate, header tidak pernah terkirim balik ke klien.
    let request_id = axum::http::HeaderName::from_static("x-request-id");

    Router::new()
        .merge(api::router())
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
}

/// Titik masuk aplikasi: baca config, jalankan healthcheck atau serve.
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = Config::from_env().map_err(anyhow::Error::msg)?;

    if cli.is_healthcheck() {
        let ok = healthcheck(&config.iam_bind);
        std::process::exit(if ok { 0 } else { 1 });
    }

    crate::telemetry::init(&config);

    let listener = tokio::net::TcpListener::bind(&config.iam_bind).await?;
    tracing::info!(addr = %config.iam_bind, "sanca listening");
    axum::serve(listener, build_app()).await?;
    Ok(())
}

/// Probe HTTP mentah ke `/healthz` lewat loopback. Exit 0 hanya kalau respons
/// mengandung status `200`. Dipakai subcommand `sanca healthcheck` (docker).
fn healthcheck(bind: &str) -> bool {
    let port = bind.rsplit(':').next().unwrap_or("8080");
    let addr = format!("127.0.0.1:{port}");

    let mut stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let request = "GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n";
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }

    let mut buf = [0u8; 1024];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => String::from_utf8_lossy(&buf[..n]).contains("200"),
        _ => false,
    }
}
