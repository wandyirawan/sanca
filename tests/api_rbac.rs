//! Test registry RBAC, penegakan middleware, dan sinkronisasi permission.
//!
//! Setiap test memakai database sementara `#[sqlx::test]` (migrasi + seed ikut
//! dijalankan) dan router hasil `build_app`, jadi yang diuji adalah jalur HTTP
//! sungguhan beserta middleware-nya.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use sanca::auth::keys::SigningKey;
use sanca::auth::password::hash_password;
use sanca::config::{Config, Environment, LogFormat};
use sanca::db::users;
use sanca::rbac::registry;
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
///
/// Permission diambil dari tabel (hasil sync), bukan dibuat ulang, supaya test
/// ikut membuktikan bahwa sync benar-benar mengisi katalog.
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

/// Login dan kembalikan access token, atau panik kalau login gagal.
async fn login(app: &Router, email: &str, app_slug: &str) -> String {
    let (status, body) = send(
        app,
        json_request(
            "POST",
            "/api/auth/login",
            json!({ "email": email, "password": PASSWORD, "app_slug": app_slug }),
            None,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "login fixture harus 200: {body}");
    body["access_token"]
        .as_str()
        .expect("access_token ada")
        .to_string()
}

#[test]
fn registry_memuat_semua_route_router() {
    // Daftar manual route yang dipasang `api::router`. Kalau ada route baru di
    // router tanpa entri registry, test ini gagal lebih dulu sebelum 500 muncul.
    let routes = [
        (Method::GET, "/healthz"),
        (Method::GET, "/.well-known/jwks.json"),
        (Method::POST, "/api/auth/login"),
        (Method::POST, "/api/auth/refresh"),
        (Method::POST, "/api/auth/logout"),
        (Method::POST, "/api/oauth/token"),
        (Method::GET, "/api/auth/me"),
        (Method::GET, "/api/roles"),
        (Method::POST, "/api/roles"),
        (Method::GET, "/api/permissions"),
    ];

    for (method, path) in routes {
        let found = registry::find(&method, path)
            .unwrap_or_else(|| panic!("route {method} {path} belum terdaftar di registry"));
        assert_eq!(found.path, path);
    }

    // Route publik tidak boleh punya permission.
    for route in registry::ROUTES {
        if route.scope == registry::AppScope::Public {
            assert!(
                route.permission.is_none(),
                "route publik {} masih punya permission",
                route.path
            );
        }
    }
}

#[test]
fn permission_registry_unik_dan_terurut() {
    let permissions = registry::permissions();

    assert_eq!(
        permissions,
        vec!["auth:me", "role:read", "role:write"],
        "katalog permission registry berubah; periksa handler dan test"
    );

    let unique: std::collections::BTreeSet<_> = permissions.iter().collect();
    assert_eq!(
        unique.len(),
        permissions.len(),
        "permission tidak boleh duplikat"
    );
    assert!(
        permissions.iter().all(|key| key.contains(':')),
        "semua permission wajib berbentuk resource:action"
    );
}

#[sqlx::test]
async fn sync_mengisi_katalog_permission_dan_idempoten(pool: PgPool) {
    sync_permissions(&pool).await;

    let jumlah: i64 = sqlx::query_scalar("SELECT count(*) FROM permissions WHERE app_id = $1")
        .bind(Uuid::parse_str(CORE_APP_ID).unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(jumlah as usize, registry::permissions().len());

    let is_system_semua: bool =
        sqlx::query_scalar("SELECT bool_and(is_system) FROM permissions WHERE app_id = $1")
            .bind(Uuid::parse_str(CORE_APP_ID).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(is_system_semua, "permission dari registry harus is_system");

    // Sync kedua tidak menambah baris.
    let baru = rbac_sync::sync(&pool)
        .await
        .expect("sync kedua harus sukses");
    assert_eq!(baru, 0, "sync harus idempoten");
}

#[sqlx::test]
async fn tanpa_token_ke_roles_ditolak_401(pool: PgPool) {
    sync_permissions(&pool).await;
    let app = build_app(test_state(pool));

    let (status, body) = send(&app, json_request("GET", "/api/roles", Value::Null, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "harus 401: {body}");
    assert_eq!(body["error"], "unauthorized");
}

#[sqlx::test]
async fn user_tanpa_permission_ditolak_403(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "kosong@example.com", "tanpa-izin", &[]).await;
    let app = build_app(test_state(pool));

    let token = login(&app, "kosong@example.com", "core").await;
    let (status, body) = send(
        &app,
        json_request("GET", "/api/roles", Value::Null, Some(&token)),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "harus 403: {body}");
    assert_eq!(body["error"], "forbidden");
}

#[sqlx::test]
async fn role_read_boleh_get_tapi_tidak_boleh_post(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "pembaca@example.com", "pembaca", &["role:read"]).await;
    let app = build_app(test_state(pool));

    let token = login(&app, "pembaca@example.com", "core").await;

    let (status, body) = send(
        &app,
        json_request("GET", "/api/roles", Value::Null, Some(&token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET harus 200: {body}");
    assert!(
        body.as_array().is_some_and(|roles| !roles.is_empty()),
        "daftar role tidak boleh kosong karena superadmin dari seed ada"
    );

    let (status, body) = send(
        &app,
        json_request(
            "POST",
            "/api/roles",
            json!({ "key": "tidak-boleh", "name": "Tidak Boleh" }),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "POST harus 403: {body}");
}

#[sqlx::test]
async fn superadmin_lolos_meski_scope_kosong(pool: PgPool) {
    sync_permissions(&pool).await;
    let user_id = fixture_user(&pool, "super@example.com", "tanpa-izin", &[]).await;
    give_superadmin(&pool, user_id).await;
    let app = build_app(test_state(pool));

    let token = login(&app, "super@example.com", "core").await;

    let (status, body) = send(
        &app,
        json_request("GET", "/api/roles", Value::Null, Some(&token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "superadmin GET harus 200: {body}");

    let (status, body) = send(
        &app,
        json_request(
            "POST",
            "/api/roles",
            json!({ "key": "role-baru", "name": "Role Baru", "description": "dibuat test" }),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "superadmin POST harus 201: {body}"
    );
    assert_eq!(body["key"], "role-baru");
    assert_eq!(body["is_system"], false);
}

#[sqlx::test]
async fn token_aud_app_lain_ditolak_401_bukan_403(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "lintas@example.com", "pembaca", &["role:read"]).await;

    sqlx::query(
        "INSERT INTO apps (id, slug, name, kind) VALUES ($1, 'lain', 'App Lain', 'service')",
    )
    .bind(Uuid::now_v7())
    .execute(&pool)
    .await
    .expect("gagal membuat app lain");

    let app = build_app(test_state(pool));

    // Token sah milik app `lain`; route `/api/roles` milik core, jadi aud salah.
    let token = login(&app, "lintas@example.com", "lain").await;
    let (status, body) = send(
        &app,
        json_request("GET", "/api/roles", Value::Null, Some(&token)),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "harus 401: {body}");
    assert_eq!(body["error"], "unauthorized");
}

#[sqlx::test]
async fn route_publik_tetap_200_tanpa_token(pool: PgPool) {
    sync_permissions(&pool).await;
    let app = build_app(test_state(pool));

    let (status, body) = send(
        &app,
        Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "healthz harus 200: {body}");
    assert_eq!(body["status"], "ok");

    let (status, body) = send(
        &app,
        Request::builder()
            .uri("/.well-known/jwks.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "jwks harus 200: {body}");
}
