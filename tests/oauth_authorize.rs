//! Test alur `GET`/`POST /oauth/authorize`: validasi permintaan, halaman consent,
//! dan penerbitan kode sekali pakai.
//!
//! Yang diuji adalah jalur HTTP sungguhan lewat `build_app`: gate sesi console,
//! penegakan registry, CSRF, dan yang paling penting — bahwa `redirect_uri` harus
//! cocok persis, bahwa `spa` tanpa PKCE ditolak, dan bahwa database hanya
//! menyimpan hash kode, bukan kode aslinya.

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
use sanca::domain::oauth::hash_code;
use sanca::middleware::csrf;
use sanca::rbac::sync as rbac_sync;
use sanca::startup::build_app;
use sanca::state::AppState;
use secrecy::SecretString;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const PASSWORD: &str = "password-uji-yang-panjang";
const CALLBACK: &str = "http://localhost:9000/cb";

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

async fn sync_permissions(pool: &PgPool) {
    rbac_sync::sync(pool)
        .await
        .expect("sync permission gagal di fixture");
}

/// User aktif di app core tanpa permission khusus: alur authorize tidak butuh
/// permission, hanya sesi yang sah.
async fn fixture_user(pool: &PgPool, email: &str) -> Uuid {
    let hash = hash_password(PASSWORD, &SecretString::from(pepper())).expect("hash password gagal");
    users::insert(pool, email, &hash, "Penguji")
        .await
        .expect("gagal membuat user fixture")
        .id
}

/// App tujuan dengan satu `redirect_uri` terdaftar.
async fn fixture_app(pool: &PgPool, slug: &str, kind: AppKind, redirect_uri: &str) -> Uuid {
    let app = apps::insert(pool, slug, &format!("App {slug}"), kind, "")
        .await
        .expect("gagal membuat app fixture");

    sqlx::query("UPDATE apps SET redirect_uris = ARRAY[$2]::text[] WHERE id = $1")
        .bind(app.id)
        .bind(redirect_uri)
        .execute(pool)
        .await
        .expect("gagal mengisi redirect_uris");

    app.id
}

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

async fn get(app: &Router, uri: &str, access: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(header::COOKIE, format!("sanca_access={access}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

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
                    format!("sanca_access={access}; {}={csrf_token}", csrf::COOKIE_NAME),
                )
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

fn location(response: &axum::response::Response) -> Option<String> {
    response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// URI authorize lengkap dengan PKCE yang sah.
fn authorize_uri(client_id: &str, redirect_uri: &str, extra: &str) -> String {
    let challenge = "A".repeat(43);
    format!(
        "/oauth/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={redirect_uri}&state=xyz-123\
         &code_challenge={challenge}&code_challenge_method=S256{extra}"
    )
}

#[sqlx::test]
async fn consent_200_untuk_spa_dengan_pkce(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "izin@example.com").await;
    fixture_app(&pool, "uji-spa", AppKind::Spa, CALLBACK).await;

    let app = app(pool);
    let access = access_token(&app, "izin@example.com").await;

    let response = get(&app, &authorize_uri("uji-spa", CALLBACK, ""), &access).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "halaman consent harus 200"
    );

    let html = body_text(response).await;
    assert!(html.contains("Izinkan"), "harus ada tombol izinkan");
    assert!(html.contains("Batal"), "harus ada tombol batal");
    assert!(
        html.contains("http://localhost:9000/cb"),
        "redirect tujuan wajib ditampilkan"
    );
    assert!(html.contains("uji-spa"), "nama app wajib tampil");
}

#[sqlx::test]
async fn spa_tanpa_code_challenge_ditolak_400(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "tanpa-pkce@example.com").await;
    fixture_app(&pool, "uji-spa", AppKind::Spa, CALLBACK).await;

    let app = app(pool);
    let access = access_token(&app, "tanpa-pkce@example.com").await;

    let uri = format!(
        "/oauth/authorize?response_type=code&client_id=uji-spa&redirect_uri={CALLBACK}&state=abc"
    );
    let response = get(&app, &uri, &access).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        location(&response).is_none(),
        "permintaan tidak sah tidak boleh menghasilkan redirect"
    );
    let html = body_text(response).await;
    assert!(html.contains("PKCE"), "pesan harus menyebut PKCE");
}

#[sqlx::test]
async fn kind_service_ditolak_400(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "service@example.com").await;
    fixture_app(&pool, "uji-service", AppKind::Service, CALLBACK).await;

    let app = app(pool);
    let access = access_token(&app, "service@example.com").await;

    let response = get(&app, &authorize_uri("uji-service", CALLBACK, ""), &access).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(location(&response).is_none());
}

#[sqlx::test]
async fn redirect_uri_tidak_terdaftar_ditolak_tanpa_redirect(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "redirect@example.com").await;
    fixture_app(&pool, "uji-spa", AppKind::Spa, CALLBACK).await;

    let app = app(pool);
    let access = access_token(&app, "redirect@example.com").await;

    // Prefix yang mirip pun tidak boleh lolos: exact match, bukan awalan.
    let jahat = "http://localhost:9000/cb-lain";
    let response = get(&app, &authorize_uri("uji-spa", jahat, ""), &access).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        location(&response),
        None,
        "URI tak terdaftar tidak boleh dipakai sebagai tujuan redirect"
    );
}

#[sqlx::test]
async fn belum_login_diarahkan_ke_halaman_login(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_app(&pool, "uji-spa", AppKind::Spa, CALLBACK).await;

    let app = app(pool);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(authorize_uri("uji-spa", CALLBACK, ""))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let target = location(&response).expect("harus ada Location");
    assert!(
        target.starts_with("/console/login"),
        "harus ke halaman login, dapat: {target}"
    );
    assert!(
        target.contains("next=%2Foauth%2Fauthorize"),
        "tujuan semula harus dibawa sebagai next, dapat: {target}"
    );
}

#[sqlx::test]
async fn allow_mengembalikan_303_dengan_code_dan_state(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "setuju@example.com").await;
    fixture_app(&pool, "uji-spa", AppKind::Spa, CALLBACK).await;

    let app = app(pool);
    let access = access_token(&app, "setuju@example.com").await;

    let halaman = get(&app, &authorize_uri("uji-spa", CALLBACK, ""), &access).await;
    assert_eq!(halaman.status(), StatusCode::OK);
    let token = set_cookie(&halaman, csrf::COOKIE_NAME).expect("cookie CSRF wajib ada");

    let challenge = "A".repeat(43);
    let body = format!(
        "response_type=code&client_id=uji-spa&redirect_uri={CALLBACK}&state=xyz-123\
         &code_challenge={challenge}&code_challenge_method=S256&decision=allow&_csrf={token}"
    );
    let response = post_form(&app, "/oauth/authorize", &access, &token, &body).await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let target = location(&response).expect("harus ada Location");
    assert!(
        target.starts_with("http://localhost:9000/cb?code="),
        "kode harus dikirim ke redirect_uri: {target}"
    );
    assert!(target.contains("state=xyz-123"), "state wajib diteruskan");
}

#[sqlx::test]
async fn yang_disimpan_hanya_hash_kode(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "hash@example.com").await;
    fixture_app(&pool, "uji-spa", AppKind::Spa, CALLBACK).await;

    let app = app(pool.clone());
    let access = access_token(&app, "hash@example.com").await;

    let halaman = get(&app, &authorize_uri("uji-spa", CALLBACK, ""), &access).await;
    let token = set_cookie(&halaman, csrf::COOKIE_NAME).expect("cookie CSRF wajib ada");

    let challenge = "A".repeat(43);
    let body = format!(
        "response_type=code&client_id=uji-spa&redirect_uri={CALLBACK}\
         &code_challenge={challenge}&code_challenge_method=S256&decision=allow&_csrf={token}"
    );
    let response = post_form(&app, "/oauth/authorize", &access, &token, &body).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let target = location(&response).expect("harus ada Location");
    let code = target
        .split("code=")
        .nth(1)
        .expect("query code ada")
        .split('&')
        .next()
        .expect("nilai code ada")
        .to_string();

    let tersimpan: Vec<String> = sqlx::query_scalar("SELECT code_hash FROM oauth_codes")
        .fetch_all(&pool)
        .await
        .expect("query oauth_codes gagal");

    assert_eq!(tersimpan.len(), 1, "harus ada tepat satu kode tersimpan");
    assert_eq!(
        tersimpan[0],
        hash_code(&code),
        "yang disimpan harus SHA-256 hex dari kode"
    );
    assert_ne!(tersimpan[0], code, "kode asli tidak boleh masuk database");

    let bocor: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM oauth_codes \
         WHERE code_hash = $1 OR redirect_uri = $1 OR code_challenge = $1",
    )
    .bind(&code)
    .fetch_one(&pool)
    .await
    .expect("query pemeriksaan bocor gagal");
    assert_eq!(bocor, 0, "tidak ada kolom yang boleh berisi kode asli");
}

#[sqlx::test]
async fn deny_mengembalikan_access_denied(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "batal@example.com").await;
    fixture_app(&pool, "uji-spa", AppKind::Spa, CALLBACK).await;

    let app = app(pool);
    let access = access_token(&app, "batal@example.com").await;

    let halaman = get(&app, &authorize_uri("uji-spa", CALLBACK, ""), &access).await;
    let token = set_cookie(&halaman, csrf::COOKIE_NAME).expect("cookie CSRF wajib ada");

    let challenge = "A".repeat(43);
    let body = format!(
        "response_type=code&client_id=uji-spa&redirect_uri={CALLBACK}&state=xyz-123\
         &code_challenge={challenge}&code_challenge_method=S256&decision=deny&_csrf={token}"
    );
    let response = post_form(&app, "/oauth/authorize", &access, &token, &body).await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let target = location(&response).expect("harus ada Location");
    assert_eq!(
        target,
        "http://localhost:9000/cb?error=access_denied&state=xyz-123"
    );
}

#[sqlx::test]
async fn post_consent_tanpa_csrf_ditolak_403(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "csrf@example.com").await;
    fixture_app(&pool, "uji-spa", AppKind::Spa, CALLBACK).await;

    let app = app(pool);
    let access = access_token(&app, "csrf@example.com").await;

    let challenge = "A".repeat(43);
    let body = format!(
        "response_type=code&client_id=uji-spa&redirect_uri={CALLBACK}\
         &code_challenge={challenge}&code_challenge_method=S256&decision=allow&_csrf=salah"
    );
    let response = post_form(&app, "/oauth/authorize", &access, "benar", &body).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(location(&response).is_none());
}

#[sqlx::test]
async fn pkce_plain_ditolak_400(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "plain@example.com").await;
    fixture_app(&pool, "uji-spa", AppKind::Spa, CALLBACK).await;

    let app = app(pool);
    let access = access_token(&app, "plain@example.com").await;

    let uri = format!(
        "/oauth/authorize?response_type=code&client_id=uji-spa&redirect_uri={CALLBACK}\
         &code_challenge={}&code_challenge_method=plain",
        "A".repeat(43)
    );
    let response = get(&app, &uri, &access).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
