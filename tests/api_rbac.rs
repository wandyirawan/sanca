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
        (Method::GET, "/api/users"),
        (Method::POST, "/api/users"),
        (Method::GET, "/api/users/{id}"),
        (Method::PATCH, "/api/users/{id}"),
        (Method::GET, "/api/roles/{id}/permissions"),
        (Method::PUT, "/api/roles/{id}/permissions"),
        (Method::DELETE, "/api/roles/{id}"),
        (Method::POST, "/api/users/{id}/roles"),
        (Method::DELETE, "/api/users/{id}/roles/{role_id}"),
        (Method::GET, "/console"),
        (Method::GET, "/console/login"),
        (Method::POST, "/console/login"),
        (Method::POST, "/console/logout"),
        (Method::GET, "/assets/{*path}"),
    ];

    for (method, path) in routes {
        let found = registry::find(&method, path)
            .unwrap_or_else(|| panic!("route {method} {path} belum terdaftar di registry"));
        assert_eq!(found.path, path);
    }

    // Route publik harus publik di kedua sumbu: tanpa token, tanpa app.
    for route in registry::ROUTES {
        if route.access == registry::Access::Public {
            assert_eq!(
                route.scope,
                registry::AppScope::Public,
                "route publik {} tidak boleh terikat app",
                route.path
            );
        }
    }
}

// Katalog permission adalah kontrak antara registry route dan tabel
// `permissions`. Yang diuji di sini adalah invariannya, bukan isi persisnya:
// menambah route baru yang sah tidak boleh membuat test ini merah, tetapi
// duplikat, urutan kacau, atau format `resource:action` yang rusak harus.
#[test]
fn permission_registry_unik_dan_terurut() {
    let permissions = registry::permissions();

    let unique: std::collections::BTreeSet<_> = permissions.iter().collect();
    assert_eq!(
        unique.len(),
        permissions.len(),
        "permission tidak boleh duplikat: {permissions:?}"
    );

    for pair in permissions.windows(2) {
        assert!(
            pair[0] < pair[1],
            "permission harus terurut menaik, tetapi {:?} muncul sebelum {:?}",
            pair[0],
            pair[1]
        );
    }

    // Set minimum yang wajib ada: dipakai handler API maupun route console
    // (matriks RBAC, layar audit, dashboard). Hilangnya salah satu berarti
    // route-nya tidak lagi bisa diotorisasi.
    const WAJIB: &[&str] = &[
        "auth:me",
        "role:read",
        "role:write",
        "user:read",
        "user:write",
        "app:read",
        "app:write",
        "audit:read",
    ];
    for wajib in WAJIB {
        assert!(
            permissions.contains(wajib),
            "permission wajib {wajib:?} hilang dari registry: {permissions:?}"
        );
    }

    for key in &permissions {
        let mut bagian = key.split(':');
        let resource = bagian.next().unwrap_or_default();
        let action = bagian.next().unwrap_or_default();
        assert!(
            bagian.next().is_none(),
            "permission {key:?} harus punya tepat satu titik dua"
        );
        assert!(
            !resource.is_empty() && !action.is_empty(),
            "permission {key:?} harus berbentuk resource:action dengan kedua sisi terisi"
        );
    }
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

#[sqlx::test]
async fn user_tanpa_role_boleh_get_me_200(pool: PgPool) {
    sync_permissions(&pool).await;

    // User tanpa role sama sekali: tidak ada baris user_roles.
    let hash = hash_password(PASSWORD, &SecretString::from(pepper())).expect("hash password gagal");
    users::insert(&pool, "tanpa-role@example.com", &hash, "Tanpa Role")
        .await
        .expect("gagal membuat user tanpa role");

    let app = build_app(test_state(pool));
    let token = login(&app, "tanpa-role@example.com", "core").await;

    let (status, body) = send(
        &app,
        json_request("GET", "/api/auth/me", Value::Null, Some(&token)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "me harus 200 untuk setiap user yang login: {body}"
    );
    assert_eq!(body["app"], "core");
    assert_eq!(
        body["scope"],
        json!([]),
        "user tanpa role punya scope kosong"
    );

    // Route berpermission tetap menolak user yang sama.
    let (status, body) = send(
        &app,
        json_request("GET", "/api/roles", Value::Null, Some(&token)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "roles harus 403: {body}");
}

#[sqlx::test]
async fn anonymous_ke_me_ditolak_401(pool: PgPool) {
    sync_permissions(&pool).await;
    let app = build_app(test_state(pool));

    let (status, body) = send(&app, json_request("GET", "/api/auth/me", Value::Null, None)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "me anonim harus 401: {body}"
    );
    assert_eq!(body["error"], "unauthorized");
}

#[sqlx::test]
async fn superadmin_get_roles_tetap_200(pool: PgPool) {
    sync_permissions(&pool).await;
    let user_id = fixture_user(&pool, "super-me@example.com", "tanpa-izin", &[]).await;
    give_superadmin(&pool, user_id).await;
    let app = build_app(test_state(pool));

    let token = login(&app, "super-me@example.com", "core").await;

    let (status, body) = send(
        &app,
        json_request("GET", "/api/roles", Value::Null, Some(&token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "superadmin roles harus 200: {body}");

    let (status, body) = send(
        &app,
        json_request("GET", "/api/auth/me", Value::Null, Some(&token)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "superadmin me harus 200: {body}");
    assert_eq!(body["typ"], "user");
}

/// Id role lewat key di app core.
async fn role_id_by_key(pool: &PgPool, key: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM roles WHERE app_id = $1 AND key = $2")
        .bind(Uuid::parse_str(CORE_APP_ID).unwrap())
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|err| panic!("role {key} harus ada: {err}"))
}

/// Jumlah permission yang menempel di satu role.
async fn permission_count(pool: &PgPool, role_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM role_permissions WHERE role_id = $1")
        .bind(role_id)
        .fetch_one(pool)
        .await
        .expect("hitung permission role gagal")
}

/// Buat role kosong langsung di DB; dipakai saat yang diuji bukan pembuatannya.
async fn insert_empty_role(pool: &PgPool, key: &str) -> Uuid {
    let role_id = Uuid::now_v7();

    sqlx::query("INSERT INTO roles (id, app_id, key, name) VALUES ($1, $2, $3, $4)")
        .bind(role_id)
        .bind(Uuid::parse_str(CORE_APP_ID).unwrap())
        .bind(key)
        .bind(format!("Role {key}"))
        .execute(pool)
        .await
        .expect("gagal membuat role kosong");

    role_id
}

#[sqlx::test]
async fn grant_permission_di_luar_scope_ditolak_403(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis@example.com",
        "penulis",
        &["role:read", "role:write"],
    )
    .await;
    let role_id = insert_empty_role(&pool, "target-grant").await;
    let app = build_app(test_state(pool.clone()));
    let token = login(&app, "penulis@example.com", "core").await;

    // `user:write` tidak ada di scope pemanggil, jadi menambahkannya ke role
    // mana pun adalah eskalasi dan harus ditolak.
    let (status, body) = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/roles/{role_id}/permissions"),
            json!({ "permissions": ["role:read", "user:write"] }),
            Some(&token),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "harus 403: {body}");
    assert_eq!(
        permission_count(&pool, role_id).await,
        0,
        "penolakan tidak boleh menyisakan perubahan setengah jadi"
    );
}

#[sqlx::test]
async fn grant_dalam_scope_tetap_boleh_200(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis-izin@example.com",
        "penulis-izin",
        &["role:read", "role:write"],
    )
    .await;
    let role_id = insert_empty_role(&pool, "target-dalam-scope").await;
    let app = build_app(test_state(pool.clone()));
    let token = login(&app, "penulis-izin@example.com", "core").await;

    let (status, body) = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/roles/{role_id}/permissions"),
            json!({ "permissions": ["role:read"] }),
            Some(&token),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "harus 200: {body}");
    assert_eq!(body["permissions"], json!(["role:read"]));

    let (status, body) = send(
        &app,
        json_request(
            "GET",
            &format!("/api/roles/{role_id}/permissions"),
            Value::Null,
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET harus 200: {body}");
    assert_eq!(body["permissions"], json!(["role:read"]));
}

#[sqlx::test]
async fn assign_role_superadmin_ke_diri_sendiri_ditolak_403(pool: PgPool) {
    sync_permissions(&pool).await;
    let user_id = fixture_user(&pool, "naik@example.com", "naik", &["role:write"]).await;
    let superadmin_id = role_id_by_key(&pool, "superadmin").await;
    let app = build_app(test_state(pool.clone()));
    let token = login(&app, "naik@example.com", "core").await;

    let (status, body) = send(
        &app,
        json_request(
            "POST",
            &format!("/api/users/{user_id}/roles"),
            json!({ "role_id": superadmin_id }),
            Some(&token),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "harus 403: {body}");

    let menempel: i64 =
        sqlx::query_scalar("SELECT count(*) FROM user_roles WHERE user_id = $1 AND role_id = $2")
            .bind(user_id)
            .bind(superadmin_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(menempel, 0, "role superadmin tidak boleh menempel");
}

#[sqlx::test]
async fn role_is_system_tidak_bisa_diubah_atau_dihapus(pool: PgPool) {
    sync_permissions(&pool).await;
    let admin_id = fixture_user(&pool, "super-beku@example.com", "super-beku", &[]).await;
    give_superadmin(&pool, admin_id).await;
    let superadmin_id = role_id_by_key(&pool, "superadmin").await;
    let app = build_app(test_state(pool.clone()));
    let token = login(&app, "super-beku@example.com", "core").await;

    // Superadmin sekalipun tidak boleh mengubah isi role sistem.
    let (status, body) = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/roles/{superadmin_id}/permissions"),
            json!({ "permissions": ["role:read"] }),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "PUT harus 403: {body}");

    // Role sistem juga tidak bisa dihapus.
    let (status, body) = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/roles/{superadmin_id}"),
            Value::Null,
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "DELETE harus 403: {body}");

    let masih_ada: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM roles WHERE id = $1)")
        .bind(superadmin_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(masih_ada, "role superadmin harus tetap ada");
}

#[sqlx::test]
async fn superadmin_kelola_role_lalu_assign_dan_unassign(pool: PgPool) {
    sync_permissions(&pool).await;
    let admin_id = fixture_user(&pool, "super-kelola@example.com", "super-kelola", &[]).await;
    give_superadmin(&pool, admin_id).await;
    let auditor = fixture_user(&pool, "auditor@example.com", "auditor-lama", &[]).await;
    let app = build_app(test_state(pool.clone()));
    let token = login(&app, "super-kelola@example.com", "core").await;

    // 1. Superadmin membuat role baru.
    let (status, body) = send(
        &app,
        json_request(
            "POST",
            "/api/roles",
            json!({ "key": "auditor", "name": "Auditor" }),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "buat role harus 201: {body}");
    let role_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    // 2. Isi permission role secara eksak.
    let (status, body) = send(
        &app,
        json_request(
            "PUT",
            &format!("/api/roles/{role_id}/permissions"),
            json!({ "permissions": ["role:read"] }),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "PUT harus 200: {body}");
    assert_eq!(body["permissions"], json!(["role:read"]));

    // 3. Assign role ke user lain.
    let (status, body) = send(
        &app,
        json_request(
            "POST",
            &format!("/api/users/{auditor}/roles"),
            json!({ "role_id": role_id }),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "assign harus 204: {body}");

    // 4. Login ulang: scope token ikut memuat permission role baru.
    let token_auditor = login(&app, "auditor@example.com", "core").await;
    let (status, body) = send(
        &app,
        json_request("GET", "/api/auth/me", Value::Null, Some(&token_auditor)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "me harus 200: {body}");
    assert_eq!(body["scope"], json!(["role:read"]), "scope harus terisi");

    let (status, body) = send(
        &app,
        json_request("GET", "/api/roles", Value::Null, Some(&token_auditor)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "GET roles harus 200: {body}");

    // 5. Cabut role: login berikutnya kembali tanpa scope.
    let (status, body) = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/users/{auditor}/roles/{role_id}"),
            Value::Null,
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "unassign harus 204: {body}");

    let token_kosong = login(&app, "auditor@example.com", "core").await;
    let (status, body) = send(
        &app,
        json_request("GET", "/api/auth/me", Value::Null, Some(&token_kosong)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "me harus 200: {body}");
    assert_eq!(body["scope"], json!([]), "scope harus kosong lagi");

    // 6. Role non-sistem boleh dihapus.
    let (status, body) = send(
        &app,
        json_request(
            "DELETE",
            &format!("/api/roles/{role_id}"),
            Value::Null,
            Some(&token),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "hapus role harus 204: {body}"
    );
}
