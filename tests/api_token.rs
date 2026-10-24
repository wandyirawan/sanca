//! Test endpoint token mesin-ke-mesin `POST /api/oauth/token`.
//!
//! Semua test memakai database sementara dari `#[sqlx::test]` dan router hasil
//! `build_app`, jadi yang diuji adalah jalur HTTP sungguhan, termasuk header
//! Basic dan body form-urlencoded.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use sanca::auth::jwt::verify_access;
use sanca::auth::keys::SigningKey;
use sanca::auth::secret::{generate_client_secret, hash_client_secret};
use sanca::config::{Config, Environment, LogFormat};
use sanca::db::apps::{self, App, AppKind};
use sanca::startup::build_app;
use sanca::state::AppState;
use secrecy::SecretString;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;

/// Pepper uji 32 byte untuk secret client.
fn client_pepper() -> String {
    STANDARD.encode([9u8; 32])
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
        argon2_pepper: SecretString::from(STANDARD.encode([7u8; 32])),
        argon2_pepper_version: 1,
        client_secret_pepper: SecretString::from(client_pepper()),
        log_dir: std::env::temp_dir(),
    }
}

/// Rakit state test: key dev dibuat di memori, penghitung rate limit masih kosong.
fn test_state(pool: PgPool) -> AppState {
    let config = test_config();
    let signing = SigningKey::load_or_generate(&config).expect("gagal membuat signing key test");
    AppState::new(pool, config, signing)
}

/// Daftarkan app baru beserta satu kredensial; kembalikan app, client_id, secret.
async fn fixture_app(pool: &PgPool, slug: &str) -> (App, String, String) {
    let app = apps::insert(pool, slug, "App Uji", AppKind::Service)
        .await
        .expect("gagal membuat app fixture");

    let client_id = format!("{slug}-client");
    let secret = generate_client_secret();
    let hash = hash_client_secret(&secret, &SecretString::from(client_pepper()))
        .expect("gagal hashing secret fixture");

    apps::create_credential(pool, app.id, &client_id, &hash)
        .await
        .expect("gagal menyimpan kredensial fixture");

    (app, client_id, secret)
}

/// Request token dengan body form dan header Basic.
fn token_request(client_id: &str, secret: &str, grant_type: &str) -> Request<Body> {
    let basic = STANDARD.encode(format!("{client_id}:{secret}"));

    Request::builder()
        .method("POST")
        .uri("/api/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, format!("Basic {basic}"))
        .body(Body::from(format!("grant_type={grant_type}")))
        .unwrap()
}

/// Request token tanpa header Authorization sama sekali.
fn token_request_tanpa_auth() -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("grant_type=client_credentials"))
        .unwrap()
}

/// Kirim request dan kembalikan status + body JSON.
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

/// `GET /api/auth/me` dengan token. App pemilik route ditentukan registry,
/// bukan header dari klien.
fn me_request(token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri("/api/auth/me")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// Kredensial client untuk app `core`; dipakai menguji token service di route core.
async fn fixture_core_credential(pool: &PgPool) -> (String, String) {
    let app = apps::by_slug(pool, "core")
        .await
        .expect("query app core gagal")
        .expect("app core harus ada dari seed");

    let client_id = "core-client".to_string();
    let secret = generate_client_secret();
    let hash = hash_client_secret(&secret, &SecretString::from(client_pepper()))
        .expect("gagal hashing secret fixture");

    apps::create_credential(pool, app.id, &client_id, &hash)
        .await
        .expect("gagal menyimpan kredensial core");

    (client_id, secret)
}

#[sqlx::test]
async fn client_credentials_menerbitkan_token_service(pool: PgPool) {
    let (app_row, client_id, secret) = fixture_app(&pool, "uji-m2m").await;
    let state = test_state(pool);
    let config = state.config.clone();
    let signing = state.signing.clone();
    let app = build_app(state);

    let (status, body) = send(
        &app,
        token_request(&client_id, &secret, "client_credentials"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "token harus 200: {body}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "");
    assert_eq!(body["expires_in"], app_row.access_ttl_secs);

    let access = body["access_token"].as_str().expect("access_token ada");
    let claims =
        verify_access(&config, &signing, access, "uji-m2m").expect("token harus lolos verifikasi");

    assert_eq!(claims.typ, "service");
    assert_eq!(claims.sub, client_id);
    assert_eq!(claims.aud, "uji-m2m");
    assert_eq!(claims.azp, app_row.id.to_string());
    assert!(claims.sid.is_empty(), "token service tidak punya sesi");
    assert_eq!(claims.tv, 0);
    assert!(claims.role.is_empty());
    assert!(claims.scope.is_empty());
    assert!(claims.exp > claims.iat);
}

#[sqlx::test]
async fn secret_salah_dan_client_tidak_dikenal_selalu_401_invalid_client(pool: PgPool) {
    let (_, client_id, _secret) = fixture_app(&pool, "uji-m2m").await;
    let app = build_app(test_state(pool));

    let (status_salah, body_salah) = send(
        &app,
        token_request(&client_id, "secret-yang-salah", "client_credentials"),
    )
    .await;
    let (status_asing, body_asing) = send(
        &app,
        token_request("client-tidak-ada", "secret-apa-saja", "client_credentials"),
    )
    .await;
    let (status_tanpa, body_tanpa) = send(&app, token_request_tanpa_auth()).await;

    assert_eq!(status_salah, StatusCode::UNAUTHORIZED);
    assert_eq!(status_asing, StatusCode::UNAUTHORIZED);
    assert_eq!(status_tanpa, StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_salah, body_asing,
        "respons kredensial salah harus seragam"
    );
    assert_eq!(body_tanpa, body_salah);
    assert_eq!(body_salah["error"], "invalid_client");
}

#[sqlx::test]
async fn grant_type_lain_ditolak_400_unsupported_grant_type(pool: PgPool) {
    let (_, client_id, secret) = fixture_app(&pool, "uji-m2m").await;
    let app = build_app(test_state(pool));

    let (status, body) = send(&app, token_request(&client_id, &secret, "password")).await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "harus 400: {body}");
    assert_eq!(body["error"], "unsupported_grant_type");

    // Kosong juga bukan client_credentials.
    let (status_kosong, body_kosong) = send(&app, token_request(&client_id, &secret, "")).await;
    assert_eq!(status_kosong, StatusCode::BAD_REQUEST);
    assert_eq!(body_kosong["error"], "unsupported_grant_type");
}

#[sqlx::test]
async fn kredensial_yang_dirotasi_tidak_bisa_dipakai_lagi(pool: PgPool) {
    let (app_row, client_id, secret_lama) = fixture_app(&pool, "uji-m2m").await;
    let pepper = SecretString::from(client_pepper());

    // Rotasi: kredensial lama dicabut, kredensial baru dibuat.
    apps::revoke_credentials(&pool, app_row.id)
        .await
        .expect("gagal mencabut kredensial lama");

    let client_id_baru = "uji-m2m-client-baru";
    let secret_baru = generate_client_secret();
    let hash = hash_client_secret(&secret_baru, &pepper).expect("gagal hashing secret baru");
    apps::create_credential(&pool, app_row.id, client_id_baru, &hash)
        .await
        .expect("gagal menyimpan kredensial baru");

    let app = build_app(test_state(pool));

    let (status_lama, body_lama) = send(
        &app,
        token_request(&client_id, &secret_lama, "client_credentials"),
    )
    .await;
    assert_eq!(status_lama, StatusCode::UNAUTHORIZED);
    assert_eq!(body_lama["error"], "invalid_client");

    let (status_baru, body_baru) = send(
        &app,
        token_request(client_id_baru, &secret_baru, "client_credentials"),
    )
    .await;
    assert_eq!(
        status_baru,
        StatusCode::OK,
        "secret baru harus jalan: {body_baru}"
    );
}

#[sqlx::test]
async fn app_tidak_aktif_tidak_bisa_menerbitkan_token(pool: PgPool) {
    let (app_row, client_id, secret) = fixture_app(&pool, "uji-m2m").await;

    sqlx::query("UPDATE apps SET is_active = false WHERE id = $1")
        .bind(app_row.id)
        .execute(&pool)
        .await
        .expect("gagal menonaktifkan app");

    let app = build_app(test_state(pool));
    let (status, body) = send(
        &app,
        token_request(&client_id, &secret, "client_credentials"),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "harus 401: {body}");
    assert_eq!(body["error"], "invalid_client");
}

#[sqlx::test]
async fn token_service_ditolak_403_di_route_yang_butuh_user(pool: PgPool) {
    let (client_id, secret) = fixture_core_credential(&pool).await;
    let app = build_app(test_state(pool));

    let (status, body) = send(
        &app,
        token_request(&client_id, &secret, "client_credentials"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let access = body["access_token"].as_str().unwrap();

    // Token sah dan aud-nya cocok (core), tapi scope-nya kosong: 403, bukan 401.
    let (status_me, body_me) = send(&app, me_request(access)).await;
    assert_eq!(status_me, StatusCode::FORBIDDEN, "harus 403: {body_me}");
    assert_eq!(body_me["error"], "forbidden");
}

#[sqlx::test]
async fn token_service_tidak_bisa_dipakai_lintas_app(pool: PgPool) {
    let (_, client_id, secret) = fixture_app(&pool, "salak").await;
    fixture_app(&pool, "kelapa").await;

    let app = build_app(test_state(pool));

    let (status, body) = send(
        &app,
        token_request(&client_id, &secret, "client_credentials"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let access = body["access_token"].as_str().unwrap();

    // Token aud=salak dipakai di route app core: aud tidak cocok, jadi 401.
    let (status_lintas, body_lintas) = send(&app, me_request(access)).await;
    assert_eq!(
        status_lintas,
        StatusCode::UNAUTHORIZED,
        "harus 401: {body_lintas}"
    );
    assert_eq!(body_lintas["error"], "unauthorized");
}
