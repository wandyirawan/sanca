use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use anyhow::Context;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use sqlx::postgres::PgPoolOptions;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

use crate::api;
use crate::auth::keys::SigningKey;
use crate::cli::Cli;
use crate::config::Config;
use crate::state::AppState;

/// Batas ukuran body request. Semua endpoint saat ini hanya menerima JSON kecil,
/// jadi 16 KiB sudah longgar dan menutup body raksasa sebelum diparse.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// Merakit `Router` aplikasi lengkap dengan state dan layer observability.
///
/// Dipakai oleh `main` dan oleh test integrasi supaya wiring tidak diduplikasi.
pub fn build_app(state: AppState) -> Router {
    // Urutan layer: yang ditambahkan paling akhir = paling luar. Jadi SetRequestId
    // jalan lebih dulu (membuat id dan menaruhnya di header request), baru TraceLayer
    // membuat span yang sudah memuat id itu, lalu PropagateRequestId menyalinnya ke
    // respons. Tanpa Propagate, header tidak pernah terkirim balik ke klien.
    //
    // Penegakan registry dipasang lewat `layer`, jadi ia berjalan setelah router
    // mencocokkan route dan `MatchedPath` sudah tersedia di request extensions.
    let request_id = axum::http::HeaderName::from_static("x-request-id");

    Router::new()
        .merge(api::router())
        .merge(crate::console::router())
        // session_gate ditambahkan setelah enforce, jadi ia berjalan lebih dulu:
        // cookie console diubah menjadi header Authorization sebelum registry
        // memutuskan boleh atau tidak.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::rbac::enforce::enforce,
        ))
        // Audit dipasang setelah enforce (jadi berjalan lebih dulu) supaya
        // penolakan 403 dari enforce tetap tercatat, tetapi setelah
        // session_gate supaya cookie console sudah menjadi header Authorization.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::audit::audit,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::console::session_gate,
        ))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
        .with_state(state)
}

/// Titik masuk aplikasi: baca config, jalankan healthcheck atau serve.
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    let config = Config::from_env().map_err(anyhow::Error::msg)?;

    if cli.is_healthcheck() {
        let ok = healthcheck(&config.iam_bind);
        std::process::exit(if ok { 0 } else { 1 });
    }

    crate::telemetry::init(&config);

    let state = build_state(&config).await?;

    // Permission dari registry disalin ke database sebelum server melayani
    // request, supaya konsol tidak pernah melihat katalog yang kosong.
    crate::rbac::sync::sync(&state.pool)
        .await
        .context("gagal menyinkronkan permission registry")?;

    let listener = tokio::net::TcpListener::bind(&config.iam_bind).await?;
    tracing::info!(addr = %config.iam_bind, "sanca listening");

    // ConnectInfo dipakai rate limit login untuk mengenali IP klien saat tidak
    // ada reverse proxy di depan.
    axum::serve(
        listener,
        build_app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Siapkan pool database dan signing key dari config yang sudah dibaca.
async fn build_state(config: &Config) -> anyhow::Result<AppState> {
    let database_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL wajib diisi untuk menjalankan server")?;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .context("gagal terhubung ke database")?;

    let signing = SigningKey::load_or_generate(config).context("gagal menyiapkan signing key")?;

    Ok(AppState::new(pool, config.clone(), signing))
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
