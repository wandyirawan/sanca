//! Test primitif auth: password, signing key/JWKS, access token, dan `user create`.
//!
//! Test CLI benar-benar menjalankan binary `sanca`, jadi yang diuji adalah jalur
//! yang dipakai operator, bukan fungsi internal yang mirip.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use base64::{Engine, engine::general_purpose::STANDARD};
use sanca::auth::jwt::{self, Claims};
use sanca::auth::keys::SigningKey;
use sanca::auth::password::{hash_password, verify_password};
use sanca::config::{Config, Environment, LogFormat};
use sanca::db::rbac;
use secrecy::SecretString;

/// Pepper 32 byte untuk test; dibuat di sini supaya tidak ada nilai rahasia di repo.
fn test_pepper() -> String {
    STANDARD.encode([7u8; 32])
}

fn config_with(key_dir: Option<PathBuf>) -> Config {
    Config {
        iam_bind: "127.0.0.1:0".into(),
        environment: Environment::Dev,
        log_format: LogFormat::Pretty,
        iam_public_url: "https://iam.test".into(),
        jwt_kid: "test-kid".into(),
        jwt_private_key_pem: None,
        jwt_private_key_path: None,
        sanca_key_dir: key_dir,
        argon2_pepper: SecretString::from(test_pepper()),
        argon2_pepper_version: 1,
        log_dir: std::env::temp_dir(),
    }
}

fn claims(iss: &str, aud: &str, exp_offset: i64) -> Claims {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    Claims {
        iss: iss.to_string(),
        sub: "0199c0de-0000-7000-8000-000000000001".into(),
        aud: aud.to_string(),
        azp: "0199c0de-0000-7000-8000-000000000002".into(),
        sid: "0199c0de-0000-7000-8000-000000000003".into(),
        typ: "user".into(),
        role: vec!["admin".into()],
        scope: vec!["user:read".into()],
        tv: 0,
        jti: "0199c0de-0000-7000-8000-000000000004".into(),
        iat: now,
        exp: now + exp_offset,
    }
}

/// Jalankan `sanca user create` sungguhan, seperti yang dipakai operator.
fn jalankan_user_create(database_url: &str, email: &str, superadmin: bool) -> std::process::Output {
    let mut args = vec![
        "user".to_string(),
        "create".to_string(),
        "--email".to_string(),
        email.to_string(),
        "--password-stdin".to_string(),
        "--display-name".to_string(),
        "Uji CLI".to_string(),
    ];
    if superadmin {
        args.push("--superadmin".to_string());
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_sanca"))
        .args(&args)
        .env("DATABASE_URL", database_url)
        .env("ARGON2_PEPPER", test_pepper())
        .env("ARGON2_PEPPER_VERSION", "1")
        .env("SANCA_ENV", "dev")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("jalankan binary sanca");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"password-uji-yang-panjang")
        .expect("tulis password");

    child.wait_with_output().expect("tunggu proses")
}

/// Id app `core` hasil seed `0002_seed_core_app.sql`.
async fn app_core_id(pool: &sqlx::PgPool) -> uuid::Uuid {
    sqlx::query_scalar!(r#"SELECT id FROM apps WHERE slug = 'core'"#)
        .fetch_one(pool)
        .await
        .expect("app core harus ada; jalankan seed core")
}

#[test]
fn password_hash_lalu_verify_berhasil() {
    let pepper = SecretString::from(test_pepper());
    let hash = hash_password("kalimat-rahasia-panjang", &pepper).expect("hash");

    assert!(
        hash.starts_with("$argon2id$"),
        "hash harus PHC argon2id: {hash}"
    );
    assert!(verify_password("kalimat-rahasia-panjang", &hash, 1, &pepper).expect("verify"));
}

#[test]
fn password_salah_ditolak() {
    let pepper = SecretString::from(test_pepper());
    let hash = hash_password("kalimat-rahasia-panjang", &pepper).expect("hash");

    assert!(!verify_password("kalimat-rahasia-panjangX", &hash, 1, &pepper).expect("verify"));
}

#[test]
fn password_kurang_dari_dua_belas_karakter_ditolak() {
    let pepper = SecretString::from(test_pepper());
    let err = hash_password("sebelas-ok!", &pepper).unwrap_err();

    assert_eq!(err.to_string(), "password minimal 12 karakter");
}

#[test]
fn pepper_berbeda_tidak_bisa_verifikasi() {
    let pepper_a = SecretString::from(test_pepper());
    let pepper_b = SecretString::from(STANDARD.encode([9u8; 32]));

    let hash = hash_password("kalimat-rahasia-panjang", &pepper_a).expect("hash");

    assert!(!verify_password("kalimat-rahasia-panjang", &hash, 1, &pepper_b).expect("verify"));
}

#[test]
fn access_token_bisa_ditandatangani_dan_diverifikasi() {
    let config = config_with(None);
    let keys = SigningKey::load_or_generate(&config).expect("key");
    let claims = claims(&config.iam_public_url, "core", 900);

    let token = jwt::sign_access(&keys, &claims).expect("sign");
    let decoded = jwt::verify_access(&config, &keys, &token, "core").expect("verify");

    assert_eq!(decoded, claims);
}

#[test]
fn audience_salah_ditolak() {
    let config = config_with(None);
    let keys = SigningKey::load_or_generate(&config).expect("key");
    let token =
        jwt::sign_access(&keys, &claims(&config.iam_public_url, "salak", 900)).expect("sign");

    assert_eq!(
        jwt::verify_access(&config, &keys, &token, "core").unwrap_err(),
        jwt::JwtError::BadAudience
    );
}

#[test]
fn token_kedaluwarsa_ditolak() {
    let config = config_with(None);
    let keys = SigningKey::load_or_generate(&config).expect("key");
    let token =
        jwt::sign_access(&keys, &claims(&config.iam_public_url, "core", -3600)).expect("sign");

    assert_eq!(
        jwt::verify_access(&config, &keys, &token, "core").unwrap_err(),
        jwt::JwtError::Expired
    );
}

#[test]
fn key_dimuat_dari_sanca_key_dir_dan_jwks_lengkap() {
    let dir = std::env::temp_dir().join(format!("sanca-key-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let config = config_with(Some(dir.clone()));
    let generated = SigningKey::load_or_generate(&config).expect("generate key dev");

    // File <kid>.pem harus benar-benar ada, dengan izin 0600.
    let path = dir.join("test-kid.pem");
    let pem = std::fs::read(&path).expect("file key harus ditulis");
    assert!(pem.starts_with(b"-----BEGIN"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "private key wajib 0600");
    }

    // Muat ulang: harus memakai file yang sama, bukan generate baru.
    let loaded = SigningKey::load_or_generate(&config).expect("load key");
    assert_eq!(loaded.kid, "test-kid");

    let jwks = loaded.jwks_json();
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["use"], "sig");
    assert_eq!(key["alg"], "RS256");
    assert_eq!(key["kid"], "test-kid");
    assert!(key["n"].as_str().is_some_and(|n| n.len() > 300));
    assert_eq!(key["e"], "AQAB");

    // Public key hasil rakitan DER harus sama dengan milik key yang di-generate.
    assert_eq!(loaded.public_pem, generated.public_pem);
    assert!(loaded.public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cli_user_create_menyimpan_superadmin() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("lewati: DATABASE_URL tidak diset, test CLI butuh database");
        return;
    };

    let email = format!("cli-test-{}@sanca.test", std::process::id());
    let password = "password-uji-yang-panjang";

    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("koneksi database test");

    let mut child = Command::new(env!("CARGO_BIN_EXE_sanca"))
        .args([
            "user",
            "create",
            "--email",
            &email,
            "--password-stdin",
            "--superadmin",
            "--display-name",
            "Uji CLI",
        ])
        .env("DATABASE_URL", &database_url)
        .env("ARGON2_PEPPER", test_pepper())
        .env("ARGON2_PEPPER_VERSION", "1")
        .env("SANCA_ENV", "dev")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("jalankan binary sanca");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(password.as_bytes())
        .expect("tulis password");

    let output = child.wait_with_output().expect("tunggu proses");
    assert!(
        output.status.success(),
        "user create gagal: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&email),
        "output harus memuat email: {stdout}"
    );
    assert!(!stdout.contains(password), "password tidak boleh tercetak");

    let row = sqlx::query!(
        r#"SELECT is_superadmin, password_hash, pepper_version FROM users WHERE email = $1::citext"#,
        email
    )
    .fetch_one(&pool)
    .await
    .expect("user harus tersimpan");

    assert!(row.is_superadmin, "user harus superadmin");
    assert_eq!(row.pepper_version, 1);

    let pepper = SecretString::from(test_pepper());
    assert!(
        verify_password(password, &row.password_hash, row.pepper_version, &pepper)
            .expect("verifikasi hash tersimpan")
    );

    sqlx::query!(r#"DELETE FROM users WHERE email = $1::citext"#, email)
        .execute(&pool)
        .await
        .expect("bersihkan user uji");
}

/// `user create --superadmin` harus ikut menulis `user_roles` di app `core`,
/// karena klaim `role` pada token dibaca dari sana, bukan dari `is_superadmin`.
#[tokio::test]
async fn cli_user_create_superadmin_mendapat_role_superadmin_app_core() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("lewati: DATABASE_URL tidak diset, test CLI butuh database");
        return;
    };

    let email = format!("cli-role-{}@sanca.test", std::process::id());
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("koneksi database test");

    let output = jalankan_user_create(&database_url, &email, true);
    assert!(
        output.status.success(),
        "user create gagal: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let app_core = app_core_id(&pool).await;
    let user_id = sqlx::query_scalar!(r#"SELECT id FROM users WHERE email = $1::citext"#, email)
        .fetch_one(&pool)
        .await
        .expect("user harus tersimpan");

    let roles = rbac::resolve_roles(&pool, user_id, app_core)
        .await
        .expect("resolve role");

    assert_eq!(
        roles,
        vec!["superadmin".to_string()],
        "admin harus punya role superadmin di app core"
    );

    sqlx::query!(r#"DELETE FROM users WHERE id = $1"#, user_id)
        .execute(&pool)
        .await
        .expect("bersihkan user uji");
}

/// Tanpa `--superadmin`: tidak ada baris `user_roles` sama sekali.
#[tokio::test]
async fn cli_user_create_tanpa_superadmin_tidak_punya_role() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        eprintln!("lewati: DATABASE_URL tidak diset, test CLI butuh database");
        return;
    };

    let email = format!("cli-biasa-{}@sanca.test", std::process::id());
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("koneksi database test");

    let output = jalankan_user_create(&database_url, &email, false);
    assert!(
        output.status.success(),
        "user create gagal: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let app_core = app_core_id(&pool).await;
    let user_id = sqlx::query_scalar!(r#"SELECT id FROM users WHERE email = $1::citext"#, email)
        .fetch_one(&pool)
        .await
        .expect("user harus tersimpan");

    let roles = rbac::resolve_roles(&pool, user_id, app_core)
        .await
        .expect("resolve role");

    assert!(
        roles.is_empty(),
        "user biasa tidak boleh punya role: {roles:?}"
    );

    sqlx::query!(r#"DELETE FROM users WHERE id = $1"#, user_id)
        .execute(&pool)
        .await
        .expect("bersihkan user uji");
}
