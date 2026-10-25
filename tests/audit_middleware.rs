//! Test middleware audit: apa yang dicatat, apa yang tidak, dan seperti apa
//! bentuk barisnya.
//!
//! Semua test memakai `build_app` dan database sementara `#[sqlx::test]`, jadi
//! urutan layer (session_gate → audit → enforce → handler) yang diuji adalah
//! urutan yang sama dengan produksi. Penulisan audit sengaja tidak menahan
//! respons, jadi test menunggu baris muncul dengan batas waktu, bukan
//! menganggapnya langsung ada.

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use sanca::auth::keys::SigningKey;
use sanca::auth::password::hash_password;
use sanca::config::{Config, Environment, LogFormat};
use sanca::db::audit;
use sanca::db::users;
use sanca::rbac::sync as rbac_sync;
use sanca::startup::build_app;
use sanca::state::AppState;
use secrecy::SecretString;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// App `core` dari migrasi seed.
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
        client_secret_pepper: SecretString::from(STANDARD.encode([9u8; 32])),
        log_dir: std::env::temp_dir(),
    }
}

/// Router lengkap dengan state test.
fn test_app(pool: PgPool) -> Router {
    let config = test_config();
    let signing = SigningKey::load_or_generate(&config).expect("gagal membuat signing key test");
    build_app(AppState::new(pool, config, signing))
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

/// User superadmin siap pakai; mengembalikan email-nya.
async fn superadmin_fixture(pool: &PgPool) -> String {
    let email = "admin-audit@example.com";
    let id = fixture_user(pool, email, "admin-audit", &[]).await;

    let role_id: Uuid =
        sqlx::query_scalar("SELECT id FROM roles WHERE app_id = $1 AND key = 'superadmin'")
            .bind(Uuid::parse_str(CORE_APP_ID).unwrap())
            .fetch_one(pool)
            .await
            .expect("role superadmin harus ada dari seed");

    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(id)
        .bind(role_id)
        .execute(pool)
        .await
        .expect("gagal memberi role superadmin");

    email.to_string()
}

/// Request JSON; token opsional.
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

/// Kirim request dan kembalikan status serta body teks.
async fn send(app: &Router, request: Request<Body>) -> (StatusCode, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

/// Login lewat API dan kembalikan access token.
async fn login(app: &Router, email: &str, password: &str) -> String {
    let (status, body) = send(
        app,
        json_request(
            "POST",
            "/api/auth/login",
            json!({ "email": email, "password": password, "app_slug": "core" }),
            None,
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "login fixture harus 200: {body}");
    serde_json::from_str::<Value>(&body).unwrap()["access_token"]
        .as_str()
        .expect("access_token ada")
        .to_string()
}

/// Cari satu baris audit berdasarkan aksi; `None` kalau belum mendarat.
async fn cari(pool: &PgPool, action: &str) -> Option<audit::AuditRow> {
    audit::list(pool, None, None, 100, 0)
        .await
        .expect("list audit gagal")
        .into_iter()
        .find(|row| row.action == action)
}

/// Tunggu satu baris audit muncul; gagal setelah sekitar dua detik.
///
/// Penulisan audit berjalan di task terpisah, jadi test harus memberi
/// kesempatan task itu selesai sebelum memeriksa hasilnya. Tidurnya memakai
/// `tokio::time::sleep`, bukan tidur thread, supaya runtime tetap sempat
/// menjalankan task audit yang dilepas middleware.
async fn tunggu(pool: &PgPool, action: &str) -> audit::AuditRow {
    for _ in 0..100 {
        if let Some(row) = cari(pool, action).await {
            return row;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let semua = audit::list(pool, None, None, 100, 0)
        .await
        .expect("list audit gagal");
    let ada: Vec<String> = semua
        .iter()
        .map(|row| {
            format!(
                "{} {} {}",
                row.action,
                row.method,
                row.status_code.unwrap_or(0)
            )
        })
        .collect();

    panic!("event audit {action} tidak muncul dalam dua detik; yang ada: {ada:?}");
}

/// Jumlah seluruh baris audit; dipakai untuk membuktikan tidak ada pencatatan.
async fn jumlah_audit(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(pool)
        .await
        .expect("hitung audit gagal")
}

#[sqlx::test]
async fn login_berhasil_dicatat_sebagai_auth_login(pool: PgPool) {
    sync_permissions(&pool).await;
    let admin = superadmin_fixture(&pool).await;
    let app = test_app(pool.clone());

    login(&app, &admin, PASSWORD).await;

    let row = tunggu(&pool, "auth.login").await;
    assert_eq!(
        row.app_slug, "core",
        "login console/API selalu milik app core"
    );
    assert_eq!(row.status_code, Some(200));
    assert_eq!(row.path, "/api/auth/login");
    assert!(row.actor_user_id.is_some(), "pelaku login harus user nyata");
}

#[sqlx::test]
async fn login_gagal_dicatat_tanpa_password(pool: PgPool) {
    sync_permissions(&pool).await;
    let admin = superadmin_fixture(&pool).await;
    let app = test_app(pool.clone());

    let salah = "password-salah-yang-panjang";
    let (status, _) = send(
        &app,
        json_request(
            "POST",
            "/api/auth/login",
            json!({ "email": admin, "password": salah, "app_slug": "core" }),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let row = tunggu(&pool, "auth.login_failed").await;
    assert_eq!(row.app_slug, "core");
    assert_eq!(row.status_code, Some(401));
    assert!(
        row.actor_user_id.is_none(),
        "pelaku gagal login tidak dikenal"
    );

    let metadata: String =
        sqlx::query_scalar("SELECT metadata::text FROM audit_events WHERE id = $1")
            .bind(row.id)
            .fetch_one(&pool)
            .await
            .expect("metadata audit gagal dibaca");

    assert!(
        !metadata.contains(salah),
        "metadata tidak boleh memuat password: {metadata}"
    );
    assert!(
        !metadata.contains(&admin),
        "metadata tidak boleh memuat email: {metadata}"
    );
}

#[sqlx::test]
async fn get_users_dicatat_dengan_path_template(pool: PgPool) {
    sync_permissions(&pool).await;
    let admin = superadmin_fixture(&pool).await;
    let app = test_app(pool.clone());
    let token = login(&app, &admin, PASSWORD).await;

    let (status, _) = send(
        &app,
        Request::builder()
            .uri("/api/users")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let row = tunggu(&pool, "user.read").await;
    assert_eq!(
        row.path, "/api/users",
        "path yang dicatat harus template route, bukan URL mentah"
    );
    assert_eq!(row.method, "GET");
    assert_eq!(row.status_code, Some(200));
    assert!(
        !row.request_id.is_empty(),
        "request id dari layer request-id wajib ikut tercatat"
    );
}

#[sqlx::test]
async fn post_user_dicatat_status_201(pool: PgPool) {
    sync_permissions(&pool).await;
    let admin = superadmin_fixture(&pool).await;
    let app = test_app(pool.clone());
    let token = login(&app, &admin, PASSWORD).await;

    let (status, body) = send(
        &app,
        json_request(
            "POST",
            "/api/users",
            json!({
                "email": "baru-audit@example.com",
                "password": PASSWORD,
                "display_name": "User Baru",
            }),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "pembuatan user harus 201: {body}"
    );

    let row = tunggu(&pool, "user.create").await;
    assert_eq!(row.path, "/api/users");
    assert_eq!(row.status_code, Some(201));
    assert_eq!(row.app_slug, "core");
}

#[sqlx::test]
async fn penolakan_403_ikut_tercatat(pool: PgPool) {
    sync_permissions(&pool).await;
    // Role tanpa permission apa pun: registry menolak GET /api/users.
    let email = "tanpa-izin@example.com";
    fixture_user(&pool, email, "kosong", &[]).await;

    let app = test_app(pool.clone());
    let token = login(&app, email, PASSWORD).await;

    let (status, _) = send(
        &app,
        Request::builder()
            .uri("/api/users")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let row = tunggu(&pool, "user.read").await;
    assert_eq!(
        row.status_code,
        Some(403),
        "penolakan enforce harus tetap meninggalkan jejak"
    );
    assert_eq!(row.path, "/api/users");
}

#[sqlx::test]
async fn healthz_dan_aset_tidak_dicatat(pool: PgPool) {
    sync_permissions(&pool).await;
    let app = test_app(pool.clone());

    let (status, _) = send(
        &app,
        Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = send(
        &app,
        Request::builder()
            .uri("/assets/app.css")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "aset statis harus tetap dilayani");

    // Beri kesempatan task audit (kalau ada yang salah pasang) menulis.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        jumlah_audit(&pool).await,
        0,
        "health check dan aset statis tidak boleh jadi noise di audit"
    );
}

#[sqlx::test]
async fn halaman_audit_menampilkan_baris_yang_baru_dibuat(pool: PgPool) {
    sync_permissions(&pool).await;
    let email = "auditor@example.com";
    fixture_user(
        &pool,
        email,
        "auditor",
        &["audit:read", "user:read", "user:write"],
    )
    .await;

    let app = test_app(pool.clone());
    let token = login(&app, email, PASSWORD).await;

    let (status, _) = send(
        &app,
        Request::builder()
            .uri("/api/users")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Tunggu dua baris yang pasti sudah ditulis sebelum halaman dibuka.
    tunggu(&pool, "auth.login").await;
    tunggu(&pool, "user.read").await;

    let (status, body) = send(
        &app,
        Request::builder()
            .uri("/console/audit")
            .header(header::COOKIE, format!("sanca_access={token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "halaman audit harus 200");

    assert!(body.contains("auth.login"), "login harus tampil: {body}");
    assert!(body.contains("user.read"), "pembacaan user harus tampil");
    assert!(
        body.contains("/api/users"),
        "path template harus tampil apa adanya"
    );
    assert!(body.contains("core"), "slug app harus tampil");
}
