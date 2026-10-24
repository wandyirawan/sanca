use std::env;

/// Alamat default yang di-listen kalau `IAM_BIND` tidak diset.
pub const DEFAULT_BIND: &str = "127.0.0.1:8080";

/// Lingkungan tempat aplikasi berjalan, memengaruhi perilaku saat runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Dev,
    Prod,
}

/// Format keluaran log yang dipilih lewat `SANCA_LOG_FORMAT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Pretty,
    Json,
}

/// Konfigurasi aplikasi yang diambil seluruhnya dari environment variable.
///
/// Nilai yang tidak valid akan langsung gagal (fail-fast); nilai yang belum
/// dipakai pada Phase 0 (misalnya `DATABASE_URL`) sengaja tidak disentuh dulu.
#[derive(Debug, Clone)]
pub struct Config {
    pub iam_bind: String,
    pub environment: Environment,
    pub log_format: LogFormat,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let iam_bind = env::var("IAM_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());

        let environment = match env::var("SANCA_ENV")
            .unwrap_or_else(|_| "dev".into())
            .as_str()
        {
            "dev" => Environment::Dev,
            "prod" => Environment::Prod,
            other => return Err(format!("SANCA_ENV harus dev|prod, dapat {other:?}")),
        };

        let log_format = match env::var("SANCA_LOG_FORMAT")
            .unwrap_or_else(|_| "pretty".into())
            .as_str()
        {
            "pretty" => LogFormat::Pretty,
            "json" => LogFormat::Json,
            other => {
                return Err(format!(
                    "SANCA_LOG_FORMAT harus pretty|json, dapat {other:?}"
                ));
            }
        };

        Ok(Config {
            iam_bind,
            environment,
            log_format,
        })
    }
}
