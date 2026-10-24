//! Inisialisasi tracing: dua tujuan sekaligus, stdout dan file rotasi harian.
//!
//! File log adalah kontrak operasional (Alloy men-tail `SANCA_LOG_DIR`), bukan
//! efek samping container, jadi layer file selalu dipasang kecuali direktori
//! tidak bisa dipakai — dalam kasus itu kita jatuh ke stdout saja dan berteriak.

use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::{Config, LogFormat};

/// Guard appender disimpan di static, bukan dikembalikan ke pemanggil.
///
/// `WorkerGuard` menutup thread penulis saat di-drop. Kalau guard ikut Drop di
/// akhir `init`, file log berhenti menerima baris sejak itu. `startup.rs` tidak
/// boleh diubah (lane lain memegangnya), jadi guard dijinakkan di sini selama
/// proses hidup. `OnceLock` dipakai supaya `init` kedua kali (misalnya di test)
/// tidak panic dan tidak men-drop guard yang sudah terpasang.
static FILE_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

/// Inisialisasi tracing global: stdout + file harian di `config.log_dir`.
pub fn init(config: &Config) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let mut file_writer: Option<BoxMakeWriter> = None;
    match build_file_appender(&config.log_dir) {
        Ok(appender) => {
            let (writer, guard) = tracing_appender::non_blocking(appender);
            if FILE_GUARD.set(guard).is_err() {
                // Sudah ada guard lain; writer ini tetap jalan, guard pertama
                // yang menjaga thread penulis tetap hidup.
            }
            file_writer = Some(BoxMakeWriter::new(writer));
        }
        Err(err) => {
            eprintln!(
                "peringatan: log file di {} tidak aktif ({err}); hanya menulis ke stdout",
                config.log_dir.display()
            );
        }
    }

    let ansi = matches!(config.log_format, LogFormat::Pretty);
    let stdout_layer = tracing_subscriber::fmt::layer().with_ansi(ansi);

    match config.log_format {
        LogFormat::Pretty => {
            let file_layer = file_writer.map(|writer| {
                tracing_subscriber::fmt::layer()
                    .with_writer(writer)
                    .with_ansi(false)
            });
            tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .with(file_layer)
                .init();
        }
        LogFormat::Json => {
            let stdout_layer = stdout_layer.json();
            let file_layer = file_writer.map(|writer| {
                tracing_subscriber::fmt::layer()
                    .with_writer(writer)
                    .with_ansi(false)
                    .json()
            });
            tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .with(file_layer)
                .init();
        }
    }
}

/// Siapkan appender harian `sanca.<tanggal>.log`; direktori dibuat bila belum ada.
fn build_file_appender(dir: &Path) -> Result<RollingFileAppender, String> {
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("sanca")
        .filename_suffix("log")
        .build(dir)
        .map_err(|e| e.to_string())
}
