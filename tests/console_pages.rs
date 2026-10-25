//! Test halaman console: login (dengan CSRF), sesi cookie, dan penyajian aset.
//!
//! Semua lewat `build_app`, jadi yang diuji adalah jalur HTTP sungguhan:
//! middleware sesi, penegakan registry, dan handler HTML-nya.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use sanca::auth::keys::SigningKey;
use sanca::auth::password::hash_password;
use sanca::config::{Config, Environment, LogFormat};
use sanca::db::users;
use sanca::startup::build_app;
use sanca::state::AppState;
use secrecy::SecretString;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// App `core` dari migrasi seed.
const CORE_APP_ID: &str = "0192f3a4-5b6c-7d8e-9f01-234567890abc";
/// Email fixture.
const EMAIL: &str = "rani@example.com";
/// Password fixture.
const PASSWORD: &str = "password-uji-yang-panjang";
/// Nama tampilan fixture; dipakai untuk memastikan dashboard memuat identitas.
const DISPLAY_NAME: &str = "Rani Pertiwi";

fn pepper() -> String {
    STANDARD.encode([7u8; 32])
}

fn test_config() -> Config {
    Config {
        iam_bind: "127.0.0.1:0".into(),
        environment: Environment::Dev,
        log_format: LogFormat::Pretty,
        iam_public_url: "https://iam.test".into(),
        jwt_kid: "test-kid".into(),
        jwt_private_key_pem: None,
        jwt_private_key_path: None,
        sanca_key_dir: None,
        argon2_pepper: SecretString::from(pepper()),
        argon2_pepper_version: 1,
        client_secret_pepper: SecretString::from(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [9u8; 32],
        )),
        log_dir: std::env::temp_dir(),
    }
}

fn test_state(pool: PgPool) -> AppState {
    let config = test_config();
    let signing = SigningKey::load_or_generate(&config).expect("gagal membuat signing key test");
    AppState::new(pool, config, signing)
}

fn app(pool: PgPool) -> Router {
    build_app(test_state(pool))
}

/// User aktif dengan password yang dikenal, tanpa role (dashboard tidak butuh).
async fn fixture_user(pool: &PgPool) -> Uuid {
    let hash = hash_password(PASSWORD, &SecretString::from(pepper())).expect("hash password gagal");
    let user = users::insert(pool, EMAIL, &hash, DISPLAY_NAME)
        .await
        .expect("gagal membuat user fixture");

    // App core sudah ada dari seed; cukup pastikan id-nya bisa dipakai.
    let _ = Uuid::parse_str(CORE_APP_ID).unwrap();
    user.id
}

/// Nilai satu cookie dari header `Set-Cookie` mana pun pada respons.
fn set_cookie(response: &axum::response::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|raw| {
            let pair = raw.split(';').next()?;
            let (key, value) = pair.split_once('=')?;
            (key.trim() == name).then(|| value.trim().to_string())
        })
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).to_string()
}

#[sqlx::test]
async fn halaman_login_200_dengan_tema_dan_csrf(pool: PgPool) {
    let response = app(pool)
        .oneshot(
            Request::builder()
                .uri("/console/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Cookie CSRF dipasang di respons pertama; itu yang dipakai form.
    let csrf = set_cookie(&response, "sanca_csrf").expect("cookie sanca_csrf wajib dipasang");
    assert!(!csrf.is_empty(), "token CSRF tidak boleh kosong");

    let body = body_text(response).await;
    assert!(
        body.contains("data-theme=\"tanah-malam\""),
        "tema awal harus tanah-malam"
    );
    assert!(body.contains("_csrf"), "form login wajib memuat field CSRF");
    assert!(body.contains(&csrf), "nilai _csrf harus sama dengan cookie");
}

#[sqlx::test]
async fn console_tanpa_cookie_dialihkan_ke_login(pool: PgPool) {
    let response = app(pool)
        .oneshot(
            Request::builder()
                .uri("/console")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/console/login")
    );
}

#[sqlx::test]
async fn login_tanpa_csrf_ditolak_403(pool: PgPool) {
    fixture_user(&pool).await;

    let body = format!("email={EMAIL}&password={PASSWORD}");
    let response = app(pool)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/console/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let html = body_text(response).await;
    assert!(
        html.contains("Token keamanan form tidak cocok"),
        "pesan error CSRF harus jelas"
    );
}

#[sqlx::test]
async fn login_dengan_csrf_berhasil_set_cookie_httponly(pool: PgPool) {
    fixture_user(&pool).await;
    let app = app(pool);

    // Langkah 1: ambil token CSRF dari halaman login.
    let halaman = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/console/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let csrf = set_cookie(&halaman, "sanca_csrf").expect("cookie sanca_csrf wajib ada");

    // Langkah 2: kirim form dengan token yang sama.
    let form = format!("email={EMAIL}&password={PASSWORD}&_csrf={csrf}");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/console/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, format!("sanca_csrf={csrf}"))
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/console")
    );

    let access = set_cookie(&response, "sanca_access").expect("cookie sanca_access wajib dipasang");
    assert!(!access.is_empty(), "access token tidak boleh kosong");

    let raw: Vec<&str> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    assert!(
        raw.iter().any(|line| line.starts_with("sanca_access=")
            && line.contains("HttpOnly")
            && line.contains("SameSite=Lax")),
        "cookie access wajib httpOnly dan SameSite=Lax: {raw:?}"
    );
    assert!(
        raw.iter()
            .any(|line| line.starts_with("sanca_refresh=") && line.contains("HttpOnly")),
        "cookie refresh wajib httpOnly: {raw:?}"
    );
}

#[sqlx::test]
async fn console_dengan_cookie_valid_menampilkan_nama_user(pool: PgPool) {
    fixture_user(&pool).await;
    let app = app(pool);

    // Token diambil dari jalur API supaya test ini fokus pada sesi console.
    let login = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "email": EMAIL, "password": PASSWORD, "app_slug": "core" })
                .to_string(),
        ))
        .unwrap();
    let response = app.clone().oneshot(login).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let json: serde_json::Value =
        serde_json::from_str(&body_text(response).await).expect("respons login harus JSON");
    let access = json["access_token"]
        .as_str()
        .expect("access_token ada")
        .to_string();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/console")
                .header(header::COOKIE, format!("sanca_access={access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains(DISPLAY_NAME),
        "dashboard harus memuat nama user"
    );
    assert!(
        body.contains("Ringkasan"),
        "judul halaman tidak boleh hilang"
    );
    // Token tidak boleh bocor ke HTML.
    assert!(
        !body.contains(&access),
        "access token tidak boleh muncul di body"
    );
}

#[sqlx::test]
async fn aset_css_dilayani_dengan_tipe_yang_benar(pool: PgPool) {
    let response = app(pool)
        .oneshot(
            Request::builder()
                .uri("/assets/vendor/daisyui.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/css; charset=utf-8")
    );

    let body = body_text(response).await;
    assert!(
        body.len() > 100_000,
        "daisyUI full harus utuh, bukan potongan"
    );
}

#[sqlx::test]
async fn aset_font_dilayani_sebagai_woff2(pool: PgPool) {
    let response = app(pool)
        .oneshot(
            Request::builder()
                .uri("/assets/vendor/fonts/space-grotesk-300-700-latin.woff2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("font/woff2")
    );

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..4], b"wOF2", "isi berkas harus font woff2 asli");
}
