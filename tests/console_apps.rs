//! Test layar aplikasi console: daftar, pencarian, buat, rotasi secret, dan
//! penjagaan izin.
//!
//! Yang diuji lewat `build_app` adalah jalur HTTP sungguhan: middleware sesi,
//! penegakan registry, CSRF, header `Cache-Control`, dan — yang paling penting —
//! bahwa secret hanya muncul di badan respons POST yang membuatnya, bahwa
//! rotasi benar-benar mematikan kredensial lama, dan bahwa halaman daftar tidak
//! pernah memuat secret.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use sanca::auth::keys::SigningKey;
use sanca::auth::password::hash_password;
use sanca::config::{Config, Environment, LogFormat};
use sanca::db::apps::{self, AppKind};
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

fn session_cookie(access: &str) -> String {
    format!("sanca_access={access}")
}

/// GET dengan cookie sesi console.
async fn get(app: &Router, uri: &str, access: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, session_cookie(access))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// POST form dengan cookie sesi + token CSRF yang sudah ada di cookie.
async fn post_form(
    app: &Router,
    uri: &str,
    access: &str,
    csrf_token: &str,
    body: &str,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(
                    header::COOKIE,
                    format!(
                        "{}; {}={csrf_token}",
                        session_cookie(access),
                        csrf::COOKIE_NAME
                    ),
                )
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Token CSRF dari halaman daftar aplikasi.
async fn csrf_token(app: &Router, access: &str) -> String {
    let halaman = get(app, "/console/apps", access).await;
    assert_eq!(halaman.status(), StatusCode::OK, "halaman daftar harus 200");
    set_cookie(&halaman, csrf::COOKIE_NAME).expect("cookie sanca_csrf wajib ada")
}

/// Isi elemen `<code id="...">` dari HTML kredensial.
fn extract_code(html: &str, id: &str) -> String {
    let needle = format!("id=\"{id}\"");
    let start = html
        .find(&needle)
        .unwrap_or_else(|| panic!("elemen {id} tidak ada di HTML"))
        + needle.len();
    let rest = &html[start..];
    let open = rest.find('>').expect("tag pembuka code") + 1;
    let end = rest[open..].find("</code>").expect("tag penutup code");
    rest[open..open + end].trim().to_string()
}

/// Minta access token service dengan kredensial client.
async fn service_token(
    app: &Router,
    client_id: &str,
    client_secret: &str,
) -> axum::response::Response {
    let basic = STANDARD.encode(format!("{client_id}:{client_secret}"));

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::AUTHORIZATION, format!("Basic {basic}"))
                .body(Body::from("grant_type=client_credentials"))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Buat app lewat console dan kembalikan (client_id, client_secret, id app).
async fn create_app_via_console(
    app: &Router,
    pool: &PgPool,
    access: &str,
    csrf_token: &str,
    slug: &str,
) -> (String, String, Uuid) {
    let body =
        format!("slug={slug}&name=App+{slug}&description=uji&kind=service&_csrf={csrf_token}");
    let response = post_form(app, "/console/apps", access, csrf_token, &body).await;

    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "pembuatan app harus 201"
    );
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "respons yang memuat secret wajib no-store"
    );

    let html = body_text(response).await;
    let client_id = extract_code(&html, "client-id");
    let client_secret = extract_code(&html, "client-secret");

    let app = apps::by_slug(pool, slug)
        .await
        .expect("query app gagal")
        .expect("app baru harus tersimpan");

    (client_id, client_secret, app.id)
}

#[sqlx::test]
async fn daftar_apps_200_dan_memuat_app_dari_database(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "pembaca@example.com", "pembaca", &["app:read"]).await;
    apps::insert(&pool, "salak-api", "API Salak", AppKind::Service, "")
        .await
        .expect("gagal membuat app fixture");

    let app = app(pool);
    let access = access_token(&app, "pembaca@example.com").await;

    let response = get(&app, "/console/apps", &access).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_text(response).await;
    assert!(body.contains("salak-api"), "daftar harus memuat slug app");
    assert!(body.contains("Aplikasi"), "judul halaman wajib ada");
    assert!(
        !body.contains("client_secret"),
        "halaman daftar tidak boleh memuat secret"
    );
}

#[sqlx::test]
async fn daftar_apps_tanpa_permission_ditolak_403(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "tanpa-izin@example.com", "kosong", &[]).await;

    let app = app(pool);
    let access = access_token(&app, "tanpa-izin@example.com").await;

    let response = get(&app, "/console/apps", &access).await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "tanpa app:read registry harus menolak, bukan hanya menyembunyikan menu"
    );
}

#[sqlx::test]
async fn buat_app_tanpa_csrf_ditolak_403(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis@example.com",
        "penulis",
        &["app:read", "app:write"],
    )
    .await;

    let app = app(pool);
    let access = access_token(&app, "penulis@example.com").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/console/apps")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, session_cookie(&access))
                .body(Body::from("slug=tanpa-csrf&name=Tanpa&kind=web"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn secret_tampil_sekali_lalu_hilang_dari_halaman_daftar(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis@example.com",
        "penulis",
        &["app:read", "app:write"],
    )
    .await;

    let app = app(pool.clone());
    let access = access_token(&app, "penulis@example.com").await;
    let token = csrf_token(&app, &access).await;

    let (client_id, client_secret, _) =
        create_app_via_console(&app, &pool, &access, &token, "uji-sekali").await;

    assert!(!client_secret.is_empty(), "secret harus benar-benar terisi");
    assert!(
        client_id.starts_with("uji-sekali-"),
        "client_id memuat slug: {client_id}"
    );

    // Kredensial yang ditampilkan harus benar-benar bisa dipakai.
    let issued = service_token(&app, &client_id, &client_secret).await;
    assert_eq!(
        issued.status(),
        StatusCode::OK,
        "secret yang ditampilkan harus berlaku"
    );

    // GET berikutnya tidak boleh memuat secret itu lagi.
    let ulang = get(&app, "/console/apps", &access).await;
    assert_eq!(ulang.status(), StatusCode::OK);
    let body = body_text(ulang).await;
    assert!(
        !body.contains(&client_secret),
        "secret tidak boleh muncul di halaman daftar"
    );
}

#[sqlx::test]
async fn rotasi_mematikan_kredensial_lama(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis@example.com",
        "penulis",
        &["app:read", "app:write"],
    )
    .await;

    let app = app(pool.clone());
    let access = access_token(&app, "penulis@example.com").await;
    let token = csrf_token(&app, &access).await;

    let (old_id, old_secret, app_id) =
        create_app_via_console(&app, &pool, &access, &token, "uji-rotasi").await;

    let response = post_form(
        &app,
        &format!("/console/apps/{app_id}/rotate"),
        &access,
        &token,
        &format!("_csrf={token}"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK, "rotasi harus 200");
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store"),
        "panel hasil rotasi juga wajib no-store"
    );

    let html = body_text(response).await;
    let new_id = extract_code(&html, "client-id");
    let new_secret = extract_code(&html, "client-secret");

    assert_ne!(new_id, old_id, "client_id baru harus berbeda");
    assert_ne!(new_secret, old_secret, "secret baru harus berbeda");
    assert!(
        !html.contains(&old_secret),
        "secret lama tidak boleh tampil di panel rotasi"
    );

    assert_eq!(
        service_token(&app, &old_id, &old_secret).await.status(),
        StatusCode::UNAUTHORIZED,
        "kredensial lama wajib mati setelah rotasi"
    );
    assert_eq!(
        service_token(&app, &new_id, &new_secret).await.status(),
        StatusCode::OK,
        "kredensial baru harus berlaku"
    );
}

#[sqlx::test]
async fn slug_duplikat_409_dan_slug_core_ditolak_400(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis@example.com",
        "penulis",
        &["app:read", "app:write"],
    )
    .await;
    apps::insert(&pool, "sudah-ada", "Sudah Ada", AppKind::Web, "")
        .await
        .expect("gagal membuat app fixture");

    let app = app(pool);
    let access = access_token(&app, "penulis@example.com").await;
    let token = csrf_token(&app, &access).await;

    let duplikat = post_form(
        &app,
        "/console/apps",
        &access,
        &token,
        &format!("slug=sudah-ada&name=Dobel&kind=web&_csrf={token}"),
    )
    .await;
    assert_eq!(
        duplikat.status(),
        StatusCode::CONFLICT,
        "slug duplikat adalah konflik"
    );

    let core = post_form(
        &app,
        "/console/apps",
        &access,
        &token,
        &format!("slug=core&name=Core&kind=web&_csrf={token}"),
    )
    .await;
    assert_eq!(
        core.status(),
        StatusCode::BAD_REQUEST,
        "slug core tidak boleh dibuat ulang"
    );
}

#[sqlx::test]
async fn nav_tanpa_app_read_tidak_memuat_tautan_apps(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "pembaca@example.com", "pembaca", &["user:read"]).await;

    let app = app(pool);
    let access = access_token(&app, "pembaca@example.com").await;

    let response = get(&app, "/console", &access).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_text(response).await;
    assert!(
        body.contains("/console/users"),
        "menu pengguna tetap tampil karena user:read dimiliki"
    );
    assert!(
        !body.contains("/console/apps"),
        "menu aplikasi tidak boleh dirender tanpa app:read"
    );
}
