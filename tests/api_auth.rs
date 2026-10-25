//! Test transport HTTP auth: login, me, refresh dengan rotasi, logout, JWKS,
//! dan rate limit login gagal.
//!
//! Semua test memakai database sementara dari `#[sqlx::test]` dan memanggil
//! router hasil `build_app`, jadi yang diuji adalah jalur HTTP sungguhan.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use sanca::auth::jwt::verify_access;
use sanca::auth::keys::SigningKey;
use sanca::auth::password::hash_password;
use sanca::config::{Config, Environment, LogFormat};
use sanca::db::{apps, users};
use sanca::startup::build_app;
use sanca::state::AppState;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// App yang dipakai hampir semua test; berasal dari seed migrasi.
const APP: &str = "core";
/// Id app `core` dari migrasi seed.
const CORE_APP_ID: &str = "0192f3a4-5b6c-7d8e-9f01-234567890abc";
/// Email fixture.
const EMAIL: &str = "rani@example.com";
/// Password fixture, cukup panjang untuk kebijakan hashing.
const PASSWORD: &str = "password-uji-yang-panjang";

/// Pepper uji 32 byte, sama untuk config dan hashing.
fn pepper() -> String {
    STANDARD.encode([7u8; 32])
}

/// Config dev minimal untuk test; tidak menyentuh filesystem.
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

/// Rakit state test: key dev dibuat di memori, penghitung rate limit masih kosong.
fn test_state(pool: PgPool) -> AppState {
    let config = test_config();
    let signing = SigningKey::load_or_generate(&config).expect("gagal membuat signing key test");
    AppState::new(pool, config, signing)
}

/// User aktif di app core dengan role `admin` dan permission `users.read`.
async fn fixture_user(pool: &PgPool) -> Uuid {
    let hash = hash_password(PASSWORD, &SecretString::from(pepper())).expect("hash password gagal");
    let user = users::insert(pool, EMAIL, &hash, "Rani")
        .await
        .expect("gagal membuat user fixture");

    let core_app = Uuid::parse_str(CORE_APP_ID).unwrap();
    let role_id = Uuid::now_v7();
    let permission_id = Uuid::now_v7();

    sqlx::query("INSERT INTO roles (id, app_id, key, name) VALUES ($1, $2, 'admin', 'Admin')")
        .bind(role_id)
        .bind(core_app)
        .execute(pool)
        .await
        .expect("gagal membuat role fixture");

    sqlx::query("INSERT INTO permissions (id, app_id, key, name) VALUES ($1, $2, 'users.read', 'Baca user')")
        .bind(permission_id)
        .bind(core_app)
        .execute(pool)
        .await
        .expect("gagal membuat permission fixture");

    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(pool)
        .await
        .expect("gagal menghubungkan role dan permission");

    // Route `GET /api/auth/me` butuh permission `auth:me`, jadi fixture ini
    // memilikinya juga; tanpa itu `me` akan 403, bukan 200.
    let me_permission_id = Uuid::now_v7();
    sqlx::query("INSERT INTO permissions (id, app_id, key, name) VALUES ($1, $2, 'auth:me', 'Identitas sendiri')")
        .bind(me_permission_id)
        .bind(core_app)
        .execute(pool)
        .await
        .expect("gagal membuat permission me fixture");

    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(me_permission_id)
        .execute(pool)
        .await
        .expect("gagal menghubungkan role dan permission me");

    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user.id)
        .bind(role_id)
        .execute(pool)
        .await
        .expect("gagal memberi role ke user");

    user.id
}

/// Request JSON; token opsional. App pemilik route ditentukan registry, jadi
/// klien tidak lagi mengirim header app.
fn json_request(method: &str, uri: &str, body: Value, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::USER_AGENT, "test-agent");

    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }

    builder.body(Body::from(body.to_string())).unwrap()
}

/// Kirim request ke router dan kembalikan status, JSON (null kalau kosong), header.
async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value, HeaderMap) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();

    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };

    (status, body, headers)
}

/// Body login standar.
fn login_body(email: &str, password: &str, app_slug: &str) -> Value {
    json!({ "email": email, "password": password, "app_slug": app_slug })
}

/// Login lalu kembalikan body respons.
async fn login(app: &Router, email: &str, password: &str) -> (StatusCode, Value) {
    let (status, body, _) = send(
        app,
        json_request(
            "POST",
            "/api/auth/login",
            login_body(email, password, APP),
            None,
        ),
    )
    .await;
    (status, body)
}

fn get_me(token: Option<&str>) -> Request<Body> {
    json_request("GET", "/api/auth/me", Value::Null, token)
}

#[sqlx::test]
async fn login_berhasil_lalu_me_mengembalikan_identitas(pool: PgPool) {
    let user_id = fixture_user(&pool).await;
    let state = test_state(pool);
    let app = build_app(state.clone());

    let (status, body) = login(&app, EMAIL, PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "login harus 200: {body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 900);

    let access = body["access_token"].as_str().expect("access_token ada");
    let refresh = body["refresh_token"].as_str().expect("refresh_token ada");
    assert!(!refresh.is_empty());

    let claims = verify_access(&state.config, &state.signing, access, APP)
        .expect("access token harus lolos verifikasi");
    assert_eq!(claims.aud, APP);
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.typ, "user");
    assert_eq!(claims.role, vec!["admin".to_string()]);
    assert_eq!(
        claims.scope,
        vec!["auth:me".to_string(), "users.read".to_string()]
    );

    // Tanpa token: 401.
    let (status, _, _) = send(&app, get_me(None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Dengan token: 200 dan app sesuai.
    let (status, me, _) = send(&app, get_me(Some(access))).await;
    assert_eq!(status, StatusCode::OK, "me harus 200: {me}");
    assert_eq!(me["app"], APP);
    assert_eq!(me["sub"], user_id.to_string());
    assert_eq!(me["typ"], "user");
}

#[sqlx::test]
async fn login_gagal_selalu_401_dengan_respons_seragam(pool: PgPool) {
    fixture_user(&pool).await;
    let app = build_app(test_state(pool));

    let (salah_password, body_password) = login(&app, EMAIL, "password-yang-salah").await;
    let (email_tidak_ada, body_email) = login(&app, "tidak-ada@example.com", PASSWORD).await;

    assert_eq!(salah_password, StatusCode::UNAUTHORIZED);
    assert_eq!(email_tidak_ada, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_password, body_email,
        "respons untuk password salah dan email tidak ada harus identik"
    );
    assert_eq!(body_password["error"], "unauthorized");
}

#[sqlx::test]
async fn token_app_lain_ditolak_401_bukan_403(pool: PgPool) {
    fixture_user(&pool).await;

    // App kedua: user boleh login di sana, tapi tokennya milik app itu.
    apps::insert(&pool, "lain", "App Lain", apps::AppKind::Service, "")
        .await
        .expect("gagal membuat app kedua");

    let app = build_app(test_state(pool));

    let (status, body, _) = send(
        &app,
        json_request(
            "POST",
            "/api/auth/login",
            login_body(EMAIL, PASSWORD, "lain"),
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "login ke app lain harus 200: {body}"
    );
    let token = body["access_token"].as_str().unwrap();

    // Dipakai untuk route app core: aud tidak cocok, jadi 401.
    let (status, _, _) = send(&app, get_me(Some(token))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn refresh_merotasi_token_dan_logout_mencabut_sesi(pool: PgPool) {
    fixture_user(&pool).await;
    let app = build_app(test_state(pool));

    let (status, body) = login(&app, EMAIL, PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    let refresh_lama = body["refresh_token"].as_str().unwrap().to_string();

    // Refresh pertama: sukses dan mengembalikan refresh baru.
    let (status, baru, _) = send(
        &app,
        json_request(
            "POST",
            "/api/auth/refresh",
            json!({ "refresh_token": refresh_lama }),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "refresh harus 200: {baru}");
    let refresh_baru = baru["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(refresh_baru, refresh_lama, "refresh token harus berotasi");
    assert!(!baru["access_token"].as_str().unwrap().is_empty());

    // Token lama sudah dicabut oleh rotasi.
    let (status, _, _) = send(
        &app,
        json_request(
            "POST",
            "/api/auth/refresh",
            json!({ "refresh_token": refresh_lama }),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Logout: 204, lalu refresh dengan token itu ditolak.
    let (status, _, _) = send(
        &app,
        json_request(
            "POST",
            "/api/auth/logout",
            json!({ "refresh_token": refresh_baru }),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _, _) = send(
        &app,
        json_request(
            "POST",
            "/api/auth/refresh",
            json!({ "refresh_token": refresh_baru }),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn jwks_publik_memuat_kunci_aktif(pool: PgPool) {
    let state = test_state(pool);
    let kid = state.signing.kid().to_string();
    let app = build_app(state);

    let (status, body, headers) = send(
        &app,
        Request::builder()
            .uri("/.well-known/jwks.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=300"
    );

    let key = &body["keys"][0];
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["use"], "sig");
    assert_eq!(key["alg"], "RS256");
    assert_eq!(key["kid"], kid);
    assert!(!key["n"].as_str().unwrap().is_empty());
    assert!(!key["e"].as_str().unwrap().is_empty());
}

#[sqlx::test]
async fn lima_login_gagal_membuat_percobaan_keenam_429(pool: PgPool) {
    fixture_user(&pool).await;
    let app = build_app(test_state(pool));

    let request = || {
        json_request(
            "POST",
            "/api/auth/login",
            login_body("tidak-ada@example.com", "password-yang-salah", APP),
            None,
        )
    };

    for ke in 1..=5 {
        let (status, _, _) = send(&app, request()).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "percobaan ke-{ke} harus 401"
        );
    }

    let (status, body, _) = send(&app, request()).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "harus 429: {body}");
    assert_eq!(body["error"], "too_many_requests");
}
