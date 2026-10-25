//! Test layar pengguna console: daftar, cari, buat, ubah, dan penjagaan izin.
//!
//! Semua lewat `build_app`, jadi yang diuji adalah jalur HTTP sungguhan:
//! middleware sesi, penegakan registry, CSRF, dan handler HTML-nya.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use sanca::auth::keys::SigningKey;
use sanca::auth::password::hash_password;
use sanca::config::{Config, Environment, LogFormat};
use sanca::db::users;
use sanca::middleware::csrf;
use sanca::rbac::sync as rbac_sync;
use sanca::startup::build_app;
use sanca::state::AppState;
use secrecy::SecretString;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// App `core` dari migrasi seed.
const CORE_APP_ID: &str = "0192f3a4-5b6c-7d8e-9f01-234567890abc";
/// Password fixture yang dipakai juga saat membuat user baru.
const PASSWORD: &str = "password-uji-yang-panjang";

fn pepper() -> String {
    STANDARD.encode([7u8; 32])
}

fn config_with(environment: Environment) -> Config {
    Config {
        iam_bind: "127.0.0.1:0".into(),
        environment,
        log_format: LogFormat::Pretty,
        iam_public_url: "https://iam.test".into(),
        jwt_kid: "test-kid".into(),
        jwt_private_key_pem: None,
        jwt_private_key_path: None,
        sanca_key_dir: None,
        argon2_pepper: SecretString::from(pepper()),
        argon2_pepper_version: 1,
        client_secret_pepper: SecretString::from(STANDARD.encode([9u8; 32])),
        log_dir: std::env::temp_dir(),
    }
}

fn test_state(pool: PgPool) -> AppState {
    let config = config_with(Environment::Dev);
    let signing = SigningKey::load_or_generate(&config).expect("gagal membuat signing key test");
    AppState::new(pool, config, signing)
}

fn app(pool: PgPool) -> Router {
    build_app(test_state(pool))
}

/// Isi tabel permission dari registry, seperti yang dilakukan startup.
async fn sync_permissions(pool: &PgPool) {
    rbac_sync::sync(pool)
        .await
        .expect("sync permission gagal di fixture");
}

/// Buat user aktif dengan satu role di app core berisi permission yang diminta.
async fn fixture_user(pool: &PgPool, email: &str, role_key: &str, permissions: &[&str]) -> Uuid {
    let hash = hash_password(PASSWORD, &SecretString::from(pepper())).expect("hash password gagal");
    let user = users::insert(pool, email, &hash, "Penguji")
        .await
        .expect("gagal membuat user fixture");

    let core_app = Uuid::parse_str(CORE_APP_ID).unwrap();
    let role_id = Uuid::now_v7();

    sqlx::query("INSERT INTO roles (id, app_id, key, name) VALUES ($1, $2, $3, $4)")
        .bind(role_id)
        .bind(core_app)
        .bind(role_key)
        .bind(format!("Role {role_key}"))
        .execute(pool)
        .await
        .expect("gagal membuat role fixture");

    for key in permissions {
        let permission_id: Uuid =
            sqlx::query_scalar("SELECT id FROM permissions WHERE app_id = $1 AND key = $2")
                .bind(core_app)
                .bind(key)
                .fetch_one(pool)
                .await
                .unwrap_or_else(|err| panic!("permission {key} harus ada dari sync: {err}"));

        sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
            .bind(role_id)
            .bind(permission_id)
            .execute(pool)
            .await
            .expect("gagal menghubungkan role dan permission");
    }

    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user.id)
        .bind(role_id)
        .execute(pool)
        .await
        .expect("gagal memberi role ke user");

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

/// Access token lewat API, supaya test ini fokus pada layar console.
async fn access_token(app: &Router, email: &str) -> String {
    let login = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "email": email, "password": PASSWORD, "app_slug": "core" })
                .to_string(),
        ))
        .unwrap();

    let response = app.clone().oneshot(login).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "login fixture harus berhasil"
    );

    let json: serde_json::Value =
        serde_json::from_str(&body_text(response).await).expect("respons login harus JSON");
    json["access_token"]
        .as_str()
        .expect("access_token ada")
        .to_string()
}

/// Cookie sesi console untuk satu user.
fn session_cookie(access: &str) -> String {
    format!("sanca_access={access}")
}

/// GET halaman daftar user; mengembalikan respons apa adanya.
async fn get_users(app: &Router, access: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/console/users")
                .header(header::COOKIE, session_cookie(access))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[sqlx::test]
async fn daftar_user_200_dan_memuat_email_user_lain(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "pembaca@example.com", "pembaca", &["user:read"]).await;
    fixture_user(&pool, "lain@example.com", "lain", &[]).await;

    let app = app(pool);
    let access = access_token(&app, "pembaca@example.com").await;

    let response = get_users(&app, &access).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_text(response).await;
    assert!(
        body.contains("lain@example.com"),
        "daftar harus memuat user lain"
    );
    assert!(body.contains("Pengguna"), "judul halaman wajib ada");
    assert!(
        !body.contains("password_hash"),
        "kolom sensitif tidak boleh muncul di HTML"
    );
}

#[sqlx::test]
async fn daftar_user_tanpa_permission_ditolak_403(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "tanpa-izin@example.com", "kosong", &[]).await;

    let app = app(pool);
    let access = access_token(&app, "tanpa-izin@example.com").await;

    let response = get_users(&app, &access).await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "user tanpa user:read harus ditolak registry, bukan hanya menyembunyikan menu"
    );
}

#[sqlx::test]
async fn fragmen_baris_terfilter_oleh_pencarian(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "pembaca@example.com", "pembaca", &["user:read"]).await;
    fixture_user(&pool, "salak@example.com", "salak", &[]).await;
    fixture_user(&pool, "kelapa@example.com", "kelapa", &[]).await;

    let app = app(pool);
    let access = access_token(&app, "pembaca@example.com").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/console/users/rows?q=salak")
                .header(header::COOKIE, session_cookie(&access))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        body.contains("salak@example.com"),
        "baris cocok wajib tampil"
    );
    assert!(
        !body.contains("kelapa@example.com"),
        "baris yang tidak cocok tidak boleh ikut dikirim"
    );
    assert!(
        body.contains("id=\"user-rows\""),
        "fragmen harus membawa tbody bertarget id user-rows"
    );
}

#[sqlx::test]
async fn buat_user_tanpa_csrf_ditolak_403(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis@example.com",
        "penulis",
        &["user:read", "user:write"],
    )
    .await;

    let app = app(pool);
    let access = access_token(&app, "penulis@example.com").await;

    let body = "email=baru@example.com&display_name=Baru&password=password-uji-yang-panjang";
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/console/users")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, session_cookie(&access))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn buat_user_dengan_csrf_303_dan_tersimpan(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis@example.com",
        "penulis",
        &["user:read", "user:write"],
    )
    .await;

    let app = app(pool.clone());
    let access = access_token(&app, "penulis@example.com").await;

    // Token CSRF dipasang halaman daftar; form memakai nilai yang sama.
    let halaman = get_users(&app, &access).await;
    assert_eq!(halaman.status(), StatusCode::OK);
    let csrf_token = set_cookie(&halaman, "sanca_csrf").expect("cookie sanca_csrf wajib ada");

    let form =
        format!("email=baru@example.com&display_name=Baru&password={PASSWORD}&_csrf={csrf_token}");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/console/users")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!("{}; sanca_csrf={csrf_token}", session_cookie(&access)),
                )
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
        Some("/console/users?ok=created")
    );

    let dibuat = users::by_email(&pool, "baru@example.com")
        .await
        .expect("query user baru gagal");
    assert!(dibuat.is_some(), "user baru harus benar-benar tersimpan");
}

#[sqlx::test]
async fn buat_user_email_duplikat_bukan_500_dan_pesannya_jelas(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis@example.com",
        "penulis",
        &["user:read", "user:write"],
    )
    .await;
    fixture_user(&pool, "dobel@example.com", "dobel", &[]).await;

    let app = app(pool);
    let access = access_token(&app, "penulis@example.com").await;

    let halaman = get_users(&app, &access).await;
    let csrf_token = set_cookie(&halaman, "sanca_csrf").expect("cookie sanca_csrf wajib ada");

    let form = format!(
        "email=dobel@example.com&display_name=Dobel&password={PASSWORD}&_csrf={csrf_token}"
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/console/users")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!("{}; sanca_csrf={csrf_token}", session_cookie(&access)),
                )
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "email duplikat adalah konflik, bukan kesalahan server"
    );

    let body = body_text(response).await;
    assert!(
        body.contains("sudah ada"),
        "pesan error harus menjelaskan email sudah dipakai: {body:.200}"
    );
}

#[sqlx::test]
async fn ubah_display_name_303_dan_nilai_berubah(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis@example.com",
        "penulis",
        &["user:read", "user:write"],
    )
    .await;
    let target = fixture_user(&pool, "target@example.com", "target", &[]).await;

    let app = app(pool.clone());
    let access = access_token(&app, "penulis@example.com").await;

    let halaman = get_users(&app, &access).await;
    let csrf_token = set_cookie(&halaman, "sanca_csrf").expect("cookie sanca_csrf wajib ada");

    let form = format!("display_name=Nama Baru&status=active&password=&_csrf={csrf_token}");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/console/users/{target}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!("{}; sanca_csrf={csrf_token}", session_cookie(&access)),
                )
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
        Some("/console/users?ok=updated")
    );

    let sesudah = users::detail(&pool, target)
        .await
        .expect("query detail gagal")
        .expect("user target harus ada");
    assert_eq!(sesudah.display_name, "Nama Baru");
}

#[sqlx::test]
async fn nav_dashboard_tanpa_user_read_tidak_memuat_tautan_users(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "polos@example.com", "polos", &[]).await;

    let app = app(pool);
    let access = access_token(&app, "polos@example.com").await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/console")
                .header(header::COOKIE, session_cookie(&access))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    assert!(
        !body.contains("/console/users"),
        "menu pengguna harus disembunyikan dari yang tidak punya user:read"
    );
}

#[sqlx::test]
async fn font_woff2_tidak_dikompres_gzip(pool: PgPool) {
    let response = app(pool)
        .oneshot(
            Request::builder()
                .uri("/assets/vendor/fonts/space-grotesk-300-700-latin.woff2")
                .header(header::ACCEPT_ENCODING, "gzip")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get(header::CONTENT_ENCODING).is_none(),
        "woff2 sudah termampatkan; meng-gzip-nya hanya menambah byte"
    );

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&bytes[..4], b"wOF2", "isi berkas harus tetap woff2 asli");
}

#[test]
fn cookie_csrf_memakai_secure_hanya_saat_prod() {
    let prod = csrf::cookie("token-uji".to_string(), true).to_string();
    assert!(
        prod.contains("Secure"),
        "cookie CSRF di produksi wajib Secure: {prod}"
    );

    let dev = csrf::cookie("token-uji".to_string(), false).to_string();
    assert!(
        !dev.contains("Secure"),
        "di dev (http) cookie tanpa Secure supaya login lokal jalan: {dev}"
    );
}
