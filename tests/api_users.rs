//! Test CRUD user lewat API: daftar, buat, detail, dan patch.
//!
//! Semua test memakai database sementara `#[sqlx::test]` dan router hasil
//! `build_app`, jadi middleware registry ikut berjalan seperti di produksi.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use sanca::auth::keys::SigningKey;
use sanca::auth::password::hash_password;
use sanca::config::{Config, Environment, LogFormat};
use sanca::db::users;
use sanca::rbac::sync as rbac_sync;
use sanca::startup::build_app;
use sanca::state::AppState;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// Id app `core` dari migrasi seed.
const CORE_APP_ID: &str = "0192f3a4-5b6c-7d8e-9f01-234567890abc";
/// Password fixture, cukup panjang untuk kebijakan hashing.
const PASSWORD: &str = "password-uji-yang-panjang";
/// Password pengganti saat menguji PATCH password.
const PASSWORD_BARU: &str = "password-baru-yang-panjang";

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
        client_secret_pepper: SecretString::from(STANDARD.encode([9u8; 32])),
        log_dir: std::env::temp_dir(),
    }
}

/// State test dengan signing key di memori.
fn test_state(pool: PgPool) -> AppState {
    let config = test_config();
    let signing = SigningKey::load_or_generate(&config).expect("gagal membuat signing key test");
    AppState::new(pool, config, signing)
}

/// Isi tabel permission dari registry, seperti yang dilakukan startup.
async fn sync_permissions(pool: &PgPool) {
    rbac_sync::sync(pool)
        .await
        .expect("sync permission gagal di fixture");
}

/// Buat user aktif dengan satu role di app core dan permission yang diminta.
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

/// Beri user role sistem `superadmin` milik app core.
async fn give_superadmin(pool: &PgPool, user_id: Uuid) {
    let role_id: Uuid =
        sqlx::query_scalar("SELECT id FROM roles WHERE app_id = $1 AND key = 'superadmin'")
            .bind(Uuid::parse_str(CORE_APP_ID).unwrap())
            .fetch_one(pool)
            .await
            .expect("role superadmin harus ada dari seed");

    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(role_id)
        .execute(pool)
        .await
        .expect("gagal memberi role superadmin");
}

/// User superadmin siap pakai; mengembalikan email-nya.
async fn superadmin_fixture(pool: &PgPool) -> String {
    let email = "admin-uji@example.com";
    let id = fixture_user(pool, email, "admin-uji", &[]).await;
    give_superadmin(pool, id).await;
    email.to_string()
}

/// Request JSON tanpa header app; token opsional.
fn json_request(method: &str, uri: &str, body: Value, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");

    if let Some(token) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }

    builder.body(Body::from(body.to_string())).unwrap()
}

/// Kirim request dan kembalikan status serta body JSON.
async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();

    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };

    (status, body)
}

/// Login dan kembalikan status plus body, supaya kegagalan bisa diperiksa.
async fn login_response(app: &Router, email: &str, password: &str) -> (StatusCode, Value) {
    send(
        app,
        json_request(
            "POST",
            "/api/auth/login",
            json!({ "email": email, "password": password, "app_slug": "core" }),
            None,
        ),
    )
    .await
}

/// Login dan kembalikan access token, atau panik kalau login gagal.
async fn login(app: &Router, email: &str, password: &str) -> String {
    let (status, body) = login_response(app, email, password).await;
    assert_eq!(status, StatusCode::OK, "login fixture harus 200: {body}");
    body["access_token"]
        .as_str()
        .expect("access_token ada")
        .to_string()
}

/// Body pembuatan user yang valid.
fn create_body(email: &str) -> Value {
    json!({ "email": email, "password": PASSWORD, "display_name": "User Uji" })
}

#[sqlx::test]
async fn superadmin_bisa_buat_daftar_dan_lihat_user(pool: PgPool) {
    sync_permissions(&pool).await;
    let admin = superadmin_fixture(&pool).await;
    let app = build_app(test_state(pool));
    let token = login(&app, &admin, PASSWORD).await;

    let (status, body) = send(
        &app,
        json_request(
            "POST",
            "/api/users",
            create_body("baru@example.com"),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "POST harus 201: {body}");
    assert_eq!(body["email"], "baru@example.com");
    assert_eq!(body["status"], "active");
    assert_eq!(body["is_superadmin"], false);
    assert!(
        body.get("password_hash").is_none() && body.get("pepper_version").is_none(),
        "respons tidak boleh memuat kolom sensitif: {body}"
    );

    let user_id = body["id"].as_str().expect("id ada").to_string();

    let (status, body) = send(
        &app,
        json_request("GET", "/api/users", Value::Null, Some(&token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET list harus 200: {body}");
    let daftar = body.as_array().expect("daftar user berupa array");
    assert!(
        daftar
            .iter()
            .any(|user| user["email"] == "baru@example.com"),
        "user baru harus muncul di daftar: {body}"
    );
    assert!(
        daftar
            .iter()
            .all(|user| user.get("password_hash").is_none()),
        "daftar tidak boleh memuat password_hash: {body}"
    );

    let (status, body) = send(
        &app,
        json_request(
            "GET",
            &format!("/api/users/{user_id}"),
            Value::Null,
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET detail harus 200: {body}");
    assert_eq!(body["id"], user_id);
    assert!(body.get("password_hash").is_none());
}

#[sqlx::test]
async fn email_duplikat_dijawab_409(pool: PgPool) {
    sync_permissions(&pool).await;
    let admin = superadmin_fixture(&pool).await;
    let app = build_app(test_state(pool));
    let token = login(&app, &admin, PASSWORD).await;

    let (status, body) = send(
        &app,
        json_request(
            "POST",
            "/api/users",
            create_body("kembar@example.com"),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "pembuatan pertama harus 201: {body}"
    );

    // Kapital berbeda tetap duplikat karena kolomnya citext.
    let (status, body) = send(
        &app,
        json_request(
            "POST",
            "/api/users",
            create_body("Kembar@Example.com"),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "duplikat harus 409: {body}");
    assert_eq!(body["error"], "conflict");
}

#[sqlx::test]
async fn password_pendek_dijawab_400(pool: PgPool) {
    sync_permissions(&pool).await;
    let admin = superadmin_fixture(&pool).await;
    let app = build_app(test_state(pool));
    let token = login(&app, &admin, PASSWORD).await;

    let (status, body) = send(
        &app,
        json_request(
            "POST",
            "/api/users",
            json!({ "email": "pendek@example.com", "password": "pendek" }),
            Some(&token),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "harus 400: {body}");
    assert_eq!(body["error"], "bad_request");
}

#[sqlx::test]
async fn user_read_boleh_get_tapi_tidak_boleh_post(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "pembaca-user@example.com",
        "pembaca-user",
        &["user:read"],
    )
    .await;
    let app = build_app(test_state(pool));
    let token = login(&app, "pembaca-user@example.com", PASSWORD).await;

    let (status, body) = send(
        &app,
        json_request("GET", "/api/users", Value::Null, Some(&token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET harus 200: {body}");

    let (status, body) = send(
        &app,
        json_request(
            "POST",
            "/api/users",
            create_body("dilarang@example.com"),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "POST harus 403: {body}");
}

#[sqlx::test]
async fn tanpa_permission_ditolak_dan_anonymous_401(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "kosong-user@example.com", "tanpa-izin-user", &[]).await;
    let app = build_app(test_state(pool));
    let token = login(&app, "kosong-user@example.com", PASSWORD).await;

    let (status, body) = send(
        &app,
        json_request("GET", "/api/users", Value::Null, Some(&token)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "harus 403: {body}");

    let (status, body) = send(&app, json_request("GET", "/api/users", Value::Null, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "harus 401: {body}");
}

#[sqlx::test]
async fn non_superadmin_tidak_boleh_membuat_superadmin(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis-user@example.com",
        "penulis-user",
        &["user:read", "user:write"],
    )
    .await;
    let app = build_app(test_state(pool));
    let token = login(&app, "penulis-user@example.com", PASSWORD).await;

    let (status, body) = send(
        &app,
        json_request(
            "POST",
            "/api/users",
            json!({
                "email": "naik-pangkat@example.com",
                "password": PASSWORD,
                "is_superadmin": true
            }),
            Some(&token),
        ),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "escalation harus 403: {body}"
    );

    // User biasa tetap boleh membuat user biasa.
    let (status, body) = send(
        &app,
        json_request(
            "POST",
            "/api/users",
            create_body("biasa@example.com"),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "user biasa harus 201: {body}");
}

#[sqlx::test]
async fn patch_password_menaikkan_token_version(pool: PgPool) {
    sync_permissions(&pool).await;
    let admin = superadmin_fixture(&pool).await;
    let app = build_app(test_state(pool.clone()));
    let token = login(&app, &admin, PASSWORD).await;

    let (status, body) = send(
        &app,
        json_request(
            "POST",
            "/api/users",
            create_body("ganti-sandi@example.com"),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "buat user harus 201: {body}");
    let user_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
    let versi_awal = body["token_version"].as_i64().unwrap();

    // display_name saja tidak boleh mengubah token_version.
    let (status, body) = send(
        &app,
        json_request(
            "PATCH",
            &format!("/api/users/{user_id}"),
            json!({ "display_name": "Nama Baru" }),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PATCH nama harus 200: {body}");
    assert_eq!(body["display_name"], "Nama Baru");
    assert_eq!(
        body["token_version"].as_i64().unwrap(),
        versi_awal,
        "ubah nama tidak boleh mencabut token"
    );

    let (status, body) = send(
        &app,
        json_request(
            "PATCH",
            &format!("/api/users/{user_id}"),
            json!({ "password": PASSWORD_BARU }),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PATCH password harus 200: {body}");
    assert_eq!(
        body["token_version"].as_i64().unwrap(),
        versi_awal + 1,
        "ganti password harus menaikkan token_version tepat satu"
    );

    let versi_db: i32 = sqlx::query_scalar("SELECT token_version FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("baca token_version gagal");
    assert_eq!(
        i64::from(versi_db),
        versi_awal + 1,
        "token_version di DB harus naik"
    );

    // Password baru berlaku, password lama tidak.
    let (status, _) = login_response(&app, "ganti-sandi@example.com", PASSWORD_BARU).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "login dengan password baru harus 200"
    );
    let (status, _) = login_response(&app, "ganti-sandi@example.com", PASSWORD).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "password lama harus ditolak"
    );
}

#[sqlx::test]
async fn patch_status_disabled_membuat_login_gagal(pool: PgPool) {
    sync_permissions(&pool).await;
    let admin = superadmin_fixture(&pool).await;
    let app = build_app(test_state(pool.clone()));
    let token = login(&app, &admin, PASSWORD).await;

    let (status, body) = send(
        &app,
        json_request(
            "POST",
            "/api/users",
            create_body("nonaktif@example.com"),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "buat user harus 201: {body}");
    let user_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
    let versi_awal = body["token_version"].as_i64().unwrap();

    let (status, body) = send(
        &app,
        json_request(
            "PATCH",
            &format!("/api/users/{user_id}"),
            json!({ "status": "disabled" }),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PATCH status harus 200: {body}");
    assert_eq!(body["status"], "disabled");
    assert_eq!(
        body["token_version"].as_i64().unwrap(),
        versi_awal + 1,
        "menonaktifkan akun harus menaikkan token_version"
    );

    let (status, body) = login_response(&app, "nonaktif@example.com", PASSWORD).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "login user nonaktif harus 401: {body}"
    );
}
