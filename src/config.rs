use std::env;
use std::path::PathBuf;

use base64::{Engine, engine::general_purpose::STANDARD};
use secrecy::SecretString;

/// Alamat default yang di-listen kalau `IAM_BIND` tidak diset.
pub const DEFAULT_BIND: &str = "127.0.0.1:8080";

/// Nilai `iss` default saat development; di produksi `IAM_PUBLIC_URL` wajib diisi.
pub const DEFAULT_IAM_PUBLIC_URL: &str = "http://localhost:8080";

/// `kid` default untuk key yang di-generate di development.
pub const DEFAULT_JWT_KID: &str = "sanca-dev";

/// Direktori log default. Di container, volume `sanca_logs` dipasang di path ini.
pub const DEFAULT_LOG_DIR: &str = "/var/log/sanca";

/// Versi pepper default, dipakai saat `ARGON2_PEPPER_VERSION` tidak diset.
pub const DEFAULT_PEPPER_VERSION: i16 = 1;

/// Panjang pepper yang diterima, dalam byte setelah base64 di-decode.
pub const PEPPER_LEN: usize = 32;

/// Pepper khusus development. Bukan rahasia, hanya supaya `make run` dan test
/// tidak wajib menyetel env. Di produksi env wajib diisi dan nilai ini ditolak
/// secara tidak langsung karena `ARGON2_PEPPER` kosong = error.
const DEV_PEPPER: &[u8] = b"sanca-dev-pepper-0123456789abcde";

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
/// Secret dibungkus `SecretString` supaya tidak pernah tercetak di log.
/// Fail-fast hanya berlaku untuk nilai yang memang wajib di produksi
/// (`IAM_PUBLIC_URL`, `ARGON2_PEPPER`); signing key diperiksa di
/// `auth::keys::SigningKey::load_or_generate` karena butuh akses filesystem.
#[derive(Debug, Clone)]
pub struct Config {
    pub iam_bind: String,
    pub environment: Environment,
    pub log_format: LogFormat,
    pub iam_public_url: String,
    pub jwt_kid: String,
    pub jwt_private_key_pem: Option<SecretString>,
    pub jwt_private_key_path: Option<PathBuf>,
    pub sanca_key_dir: Option<PathBuf>,
    pub argon2_pepper: SecretString,
    pub argon2_pepper_version: i16,
    pub log_dir: PathBuf,
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

        let prod = environment == Environment::Prod;

        let iam_public_url = match non_empty("IAM_PUBLIC_URL") {
            Some(url) => url,
            None if prod => return Err("IAM_PUBLIC_URL wajib diisi saat SANCA_ENV=prod".into()),
            None => DEFAULT_IAM_PUBLIC_URL.to_string(),
        };

        let jwt_kid = non_empty("JWT_KID").unwrap_or_else(|| DEFAULT_JWT_KID.to_string());

        let jwt_private_key_pem = non_empty("JWT_PRIVATE_KEY_PEM").map(SecretString::from);
        let jwt_private_key_path = non_empty("JWT_PRIVATE_KEY_PATH").map(PathBuf::from);
        let sanca_key_dir = non_empty("SANCA_KEY_DIR").map(PathBuf::from);

        let log_dir = non_empty("SANCA_LOG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_DIR));

        let argon2_pepper_version = match non_empty("ARGON2_PEPPER_VERSION") {
            Some(raw) => raw
                .parse::<i16>()
                .map_err(|_| format!("ARGON2_PEPPER_VERSION harus angka, dapat {raw:?}"))?,
            None => DEFAULT_PEPPER_VERSION,
        };

        let argon2_pepper = match non_empty("ARGON2_PEPPER") {
            Some(value) => value,
            None if prod => return Err("ARGON2_PEPPER wajib diisi saat SANCA_ENV=prod".into()),
            None => {
                eprintln!(
                    "peringatan: ARGON2_PEPPER kosong, memakai pepper development. \
                     Jangan dipakai di produksi."
                );
                STANDARD.encode(DEV_PEPPER)
            }
        };

        // Pepper harus base64 dari tepat 32 byte; salah bentuk = gagal sekarang,
        // bukan nanti saat user pertama mencoba login.
        let decoded = STANDARD
            .decode(argon2_pepper.as_bytes())
            .map_err(|_| "ARGON2_PEPPER bukan base64 yang valid".to_string())?;
        if decoded.len() != PEPPER_LEN {
            return Err(format!(
                "ARGON2_PEPPER harus {PEPPER_LEN} byte setelah di-decode, dapat {}",
                decoded.len()
            ));
        }

        Ok(Config {
            iam_bind,
            environment,
            log_format,
            iam_public_url,
            jwt_kid,
            jwt_private_key_pem,
            jwt_private_key_path,
            sanca_key_dir,
            argon2_pepper: SecretString::from(argon2_pepper),
            argon2_pepper_version,
            log_dir,
        })
    }

    /// Apakah aplikasi berjalan dengan `SANCA_ENV=prod`.
    pub fn is_prod(&self) -> bool {
        self.environment == Environment::Prod
    }
}

/// Baca env dan buang nilai kosong, supaya `FOO=` dianggap tidak diset.
fn non_empty(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
