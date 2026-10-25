//! Test grant `authorization_code` dan `refresh_token` di `POST /api/oauth/token`.
//!
//! Yang diuji adalah jalur HTTP sungguhan lewat `build_app`: kode sekali pakai
//! benar-benar hangus setelah ditukar, `redirect_uri` harus sama persis, PKCE
//! `S256` diperiksa, klien rahasia (`web`) wajib mengirim secret sementara klien
//! publik (`spa`) tidak, dan rotasi refresh token membuat token lama tidak
//! berlaku lagi. Grant lama `client_credentials` ikut diuji sebagai regresi.
//!
//! Baris `oauth_codes` dibuat lewat helper domain `issue_code` — jalur yang sama
//! dengan halaman consent — supaya test tidak mengarang bentuk data sendiri.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use sanca::auth::jwt::verify_access;
use sanca::auth::keys::SigningKey;
use sanca::auth::password::hash_password;
use sanca::config::{Config, Environment, LogFormat};
use sanca::db::apps::{self, App, AppKind};
use sanca::db::sessions;
use sanca::db::users;
use sanca::domain::apps as domain_apps;
use sanca::domain::oauth::{self, CodeGrant};
use sanca::startup::build_app;
use sanca::state::AppState;
use secrecy::SecretString;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

const PASSWORD: &str = "password-uji-yang-panjang";
const CALLBACK: &str = "http://localhost:9000/cb";
const OTHER_CALLBACK: &str = "http://localhost:9000/cb-lain";

/// `code_verifier` uji: karakter unreserved, panjang di dalam batas RFC 7636.
const VERIFIER: &str = "sanca-uji-verifier-0123456789-abcdefghij-klmnopqrst";

fn pepper() -> String {
    STANDARD.encode([7u8; 32])
}

fn client_pepper() -> String {
    STANDARD.encode([9u8; 32])
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
        client_secret_pepper: SecretString::from(client_pepper()),
        log_dir: std::env::temp_dir(),
    }
}

fn test_state(pool: PgPool) -> AppState {
    let config = config_with(Environment::Dev);
    let signing = SigningKey::load_or_generate(&config).expect("gagal membuat signing key test");
    AppState::new(pool, config, signing)
}

/// App uji beserta kredensial hidupnya. `client_id` selalu berasal dari
/// `app_credentials`, bukan slug app.
struct Fixture {
    app: App,
    client_id: String,
    secret: String,
}

async fn fixture_user(pool: &PgPool, email: &str) -> Uuid {
    let hash = hash_password(PASSWORD, &SecretString::from(pepper())).expect("hash password gagal");
    users::insert(pool, email, &hash, "Penguji")
        .await
        .expect("gagal membuat user fixture")
        .id
}

async fn fixture_app(pool: &PgPool, slug: &str, kind: AppKind, redirect: &str) -> Fixture {
    let app = apps::insert(pool, slug, &format!("App {slug}"), kind, "")
        .await
        .expect("gagal membuat app fixture");

    sqlx::query("UPDATE apps SET redirect_uris = ARRAY[$2]::text[] WHERE id = $1")
        .bind(app.id)
        .bind(redirect)
        .execute(pool)
        .await
        .expect("gagal mengisi redirect_uris");

    let issued = domain_apps::rotate_secret(pool, &config_with(Environment::Dev), app.id)
        .await
        .expect("gagal menerbitkan kredensial fixture");

    let app = apps::by_id(pool, app.id)
        .await
        .expect("query app gagal")
        .expect("app fixture harus ada");

    Fixture {
        app,
        client_id: issued.client_id,
        secret: issued.client_secret,
    }
}

/// Beri user satu permission lewat role baru di app tujuan, supaya klaim
/// `scope`/`role` pada token benar-benar berisi sesuatu.
async fn grant_permission(pool: &PgPool, app: &App, user_id: Uuid, key: &str) {
    let permission_id = Uuid::now_v7();
    let role_id = Uuid::now_v7();

    sqlx::query("INSERT INTO permissions (id, app_id, key, name) VALUES ($1, $2, $3, $3)")
        .bind(permission_id)
        .bind(app.id)
        .bind(key)
        .execute(pool)
        .await
        .expect("gagal membuat permission fixture");

    sqlx::query("INSERT INTO roles (id, app_id, key, name) VALUES ($1, $2, $3, $3)")
        .bind(role_id)
        .bind(app.id)
        .bind("penguji")
        .execute(pool)
        .await
        .expect("gagal membuat role fixture");

    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_id)
        .bind(permission_id)
        .execute(pool)
        .await
        .expect("gagal memasang permission ke role");

    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user_id)
        .bind(role_id)
        .execute(pool)
        .await
        .expect("gagal memberi role ke user");
}

/// Sesi console yang sah untuk dirujuk baris kode (`oauth_codes.session_id`
/// punya foreign key ke `sessions`).
async fn console_session(pool: &PgPool, user_id: Uuid, app_id: Uuid) -> Uuid {
    let expires_at = OffsetDateTime::now_utc() + time::Duration::hours(1);
    sessions::insert(
        pool,
        user_id,
        app_id,
        &format!("console-refresh-{}", Uuid::now_v7()),
        expires_at,
        "uji",
        None,
    )
    .await
    .expect("gagal membuat sesi console fixture")
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Buat authorization code lewat jalur domain yang sama dengan halaman consent.
async fn issue_code(
    pool: &PgPool,
    fixture: &Fixture,
    user_id: Uuid,
    session_id: Uuid,
    redirect_uri: &str,
    scope: &[String],
    challenge: Option<&str>,
) -> String {
    let grant = CodeGrant {
        app_id: fixture.app.id,
        user_id,
        session_id,
        redirect_uri,
        scope,
        code_challenge: challenge,
        challenge_method: challenge.map(|_| oauth::PKCE_METHOD_S256),
    };
    oauth::issue_code(pool, &grant)
        .await
        .expect("gagal menerbitkan kode fixture")
}

/// Susun body form dengan percent-encoding yang benar.
fn form_body(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                oauth::encode_component(key),
                oauth::encode_component(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Kirim request token; kembalikan status, body JSON, dan `Cache-Control`.
async fn send_token(
    app: &Router,
    params: &[(&str, &str)],
    basic: Option<(&str, &str)>,
) -> (StatusCode, Value, Option<String>) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");

    if let Some((client_id, secret)) = basic {
        let encoded = STANDARD.encode(format!("{client_id}:{secret}"));
        request = request.header(header::AUTHORIZATION, format!("Basic {encoded}"));
    }

    let response = app
        .clone()
        .oneshot(request.body(Body::from(form_body(params))).unwrap())
        .await
        .unwrap();

    let status = response.status();
    let cache_control = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    (status, body, cache_control)
}

#[sqlx::test]
async fn tukar_kode_spa_menghasilkan_access_dan_refresh(pool: PgPool) {
    let user_id = fixture_user(&pool, "tukar@example.com").await;
    let fixture = fixture_app(&pool, "uji-oa", AppKind::Spa, CALLBACK).await;
    grant_permission(&pool, &fixture.app, user_id, "user:read").await;

    let session_id = console_session(&pool, user_id, fixture.app.id).await;
    let challenge = pkce_challenge(VERIFIER);
    let scope = vec!["user:read".to_string()];
    let code = issue_code(
        &pool,
        &fixture,
        user_id,
        session_id,
        CALLBACK,
        &scope,
        Some(&challenge),
    )
    .await;

    let state = test_state(pool);
    let config = state.config.clone();
    let signing = state.signing.clone();
    let app = build_app(state);

    let (status, body, cache_control) = send_token(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", &fixture.client_id),
            ("code", &code),
            ("redirect_uri", CALLBACK),
            ("code_verifier", VERIFIER),
        ],
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK, "tukar kode harus 200: {body}");
    assert_eq!(cache_control.as_deref(), Some("no-store"));

    let access = body["access_token"].as_str().expect("access_token ada");
    let refresh = body["refresh_token"]
        .as_str()
        .expect("refresh_token ada pada grant ini");
    assert!(access.len() > 100, "access token harus JWT utuh");
    assert!(!refresh.is_empty(), "refresh token tidak boleh kosong");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "user:read");

    let claims = verify_access(&config, &signing, access, "uji-oa")
        .expect("access token harus lolos verifikasi");
    assert_eq!(claims.typ, "user");
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.aud, "uji-oa");
    assert_eq!(claims.azp, fixture.app.id.to_string());
    assert_eq!(claims.sid, session_id.to_string(), "sid = sesi dari kode");
    assert_eq!(claims.scope, vec!["user:read".to_string()]);
    assert_eq!(claims.role, vec!["penguji".to_string()]);
}

#[sqlx::test]
async fn kode_yang_sudah_dipakai_ditolak_invalid_grant(pool: PgPool) {
    let user_id = fixture_user(&pool, "ulang@example.com").await;
    let fixture = fixture_app(&pool, "uji-oa", AppKind::Spa, CALLBACK).await;
    let session_id = console_session(&pool, user_id, fixture.app.id).await;
    let challenge = pkce_challenge(VERIFIER);
    let code = issue_code(
        &pool,
        &fixture,
        user_id,
        session_id,
        CALLBACK,
        &[],
        Some(&challenge),
    )
    .await;

    let app = build_app(test_state(pool));

    let params = [
        ("grant_type", "authorization_code"),
        ("client_id", fixture.client_id.as_str()),
        ("code", code.as_str()),
        ("redirect_uri", CALLBACK),
        ("code_verifier", VERIFIER),
    ];

    let (status_pertama, body_pertama, _) = send_token(&app, &params, None).await;
    assert_eq!(status_pertama, StatusCode::OK, "harus 200: {body_pertama}");

    let (status_kedua, body_kedua, cache_control) = send_token(&app, &params, None).await;
    assert_eq!(status_kedua, StatusCode::BAD_REQUEST);
    assert_eq!(body_kedua["error"], "invalid_grant");
    assert_eq!(
        cache_control.as_deref(),
        Some("no-store"),
        "respons error juga tidak boleh di-cache"
    );
}

#[sqlx::test]
async fn code_verifier_salah_ditolak_invalid_grant(pool: PgPool) {
    let user_id = fixture_user(&pool, "verifier@example.com").await;
    let fixture = fixture_app(&pool, "uji-oa", AppKind::Spa, CALLBACK).await;
    let session_id = console_session(&pool, user_id, fixture.app.id).await;
    let challenge = pkce_challenge(VERIFIER);
    let code = issue_code(
        &pool,
        &fixture,
        user_id,
        session_id,
        CALLBACK,
        &[],
        Some(&challenge),
    )
    .await;

    let app = build_app(test_state(pool));

    let (status, body, _) = send_token(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", &fixture.client_id),
            ("code", &code),
            ("redirect_uri", CALLBACK),
            ("code_verifier", &"z".repeat(43)),
        ],
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "harus 400: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

#[sqlx::test]
async fn redirect_uri_berbeda_ditolak_invalid_grant(pool: PgPool) {
    let user_id = fixture_user(&pool, "redirect@example.com").await;
    let fixture = fixture_app(&pool, "uji-oa", AppKind::Spa, CALLBACK).await;
    let session_id = console_session(&pool, user_id, fixture.app.id).await;
    let challenge = pkce_challenge(VERIFIER);
    let code = issue_code(
        &pool,
        &fixture,
        user_id,
        session_id,
        CALLBACK,
        &[],
        Some(&challenge),
    )
    .await;

    let app = build_app(test_state(pool));

    let (status, body, _) = send_token(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", &fixture.client_id),
            ("code", &code),
            ("redirect_uri", OTHER_CALLBACK),
            ("code_verifier", VERIFIER),
        ],
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "harus 400: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

#[sqlx::test]
async fn kode_milik_app_lain_ditolak_invalid_grant(pool: PgPool) {
    let user_id = fixture_user(&pool, "app-lain@example.com").await;
    let pemilik = fixture_app(&pool, "uji-oa", AppKind::Spa, CALLBACK).await;
    let penukar = fixture_app(&pool, "uji-oa-lain", AppKind::Spa, CALLBACK).await;

    let session_id = console_session(&pool, user_id, pemilik.app.id).await;
    let challenge = pkce_challenge(VERIFIER);
    let code = issue_code(
        &pool,
        &pemilik,
        user_id,
        session_id,
        CALLBACK,
        &[],
        Some(&challenge),
    )
    .await;

    let app = build_app(test_state(pool));

    let (status, body, _) = send_token(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", &penukar.client_id),
            ("code", &code),
            ("redirect_uri", CALLBACK),
            ("code_verifier", VERIFIER),
        ],
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "harus 400: {body}");
    assert_eq!(body["error"], "invalid_grant");
}

#[sqlx::test]
async fn klien_web_wajib_secret_spa_tidak(pool: PgPool) {
    let user_id = fixture_user(&pool, "rahasia@example.com").await;
    let web = fixture_app(&pool, "uji-oa-web", AppKind::Web, CALLBACK).await;
    let spa = fixture_app(&pool, "uji-oa-spa", AppKind::Spa, CALLBACK).await;

    let web_session = console_session(&pool, user_id, web.app.id).await;
    // Kode web sengaja tanpa PKCE: verifier yang dikirim harus diabaikan.
    let web_code = issue_code(&pool, &web, user_id, web_session, CALLBACK, &[], None).await;
    let web_code_kedua = issue_code(&pool, &web, user_id, web_session, CALLBACK, &[], None).await;

    let spa_session = console_session(&pool, user_id, spa.app.id).await;
    let challenge = pkce_challenge(VERIFIER);
    let spa_code = issue_code(
        &pool,
        &spa,
        user_id,
        spa_session,
        CALLBACK,
        &[],
        Some(&challenge),
    )
    .await;

    let app = build_app(test_state(pool));

    let (status_tanpa, body_tanpa, _) = send_token(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", &web.client_id),
            ("code", &web_code),
            ("redirect_uri", CALLBACK),
        ],
        None,
    )
    .await;
    assert_eq!(status_tanpa, StatusCode::UNAUTHORIZED, "harus 401");
    assert_eq!(body_tanpa["error"], "invalid_client");

    // Kode yang gagal karena kredensial sudah hangus; kode baru untuk percobaan
    // dengan secret benar supaya yang diuji hanya masalah secret.
    let (status_benar, body_benar, _) = send_token(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", &web.client_id),
            ("code", &web_code_kedua),
            ("redirect_uri", CALLBACK),
            ("code_verifier", "verifier-yang-tidak-dipakai"),
        ],
        Some((&web.client_id, &web.secret)),
    )
    .await;
    assert_eq!(status_benar, StatusCode::OK, "harus 200: {body_benar}");

    let (status_spa, body_spa, _) = send_token(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", &spa.client_id),
            ("code", &spa_code),
            ("redirect_uri", CALLBACK),
            ("code_verifier", VERIFIER),
        ],
        None,
    )
    .await;
    assert_eq!(
        status_spa,
        StatusCode::OK,
        "spa tanpa secret harus 200: {body_spa}"
    );
}

#[sqlx::test]
async fn refresh_merotasi_token_dan_yang_lama_ditolak(pool: PgPool) {
    let user_id = fixture_user(&pool, "rotasi@example.com").await;
    let fixture = fixture_app(&pool, "uji-oa", AppKind::Spa, CALLBACK).await;
    grant_permission(&pool, &fixture.app, user_id, "user:read").await;

    let session_id = console_session(&pool, user_id, fixture.app.id).await;
    let challenge = pkce_challenge(VERIFIER);
    let scope = vec!["user:read".to_string()];
    let code = issue_code(
        &pool,
        &fixture,
        user_id,
        session_id,
        CALLBACK,
        &scope,
        Some(&challenge),
    )
    .await;

    let state = test_state(pool);
    let config = state.config.clone();
    let signing = state.signing.clone();
    let app = build_app(state);

    let (status, body, _) = send_token(
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", &fixture.client_id),
            ("code", &code),
            ("redirect_uri", CALLBACK),
            ("code_verifier", VERIFIER),
        ],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "tukar kode harus 200: {body}");
    let refresh_lama = body["refresh_token"]
        .as_str()
        .expect("refresh_token ada")
        .to_string();

    let (status_refresh, body_refresh, _) = send_token(
        &app,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", &fixture.client_id),
            ("refresh_token", &refresh_lama),
        ],
        None,
    )
    .await;
    assert_eq!(
        status_refresh,
        StatusCode::OK,
        "refresh harus 200: {body_refresh}"
    );

    let refresh_baru = body_refresh["refresh_token"]
        .as_str()
        .expect("refresh baru ada")
        .to_string();
    assert_ne!(refresh_baru, refresh_lama, "refresh token harus berotasi");
    assert_eq!(body_refresh["scope"], "user:read");

    let access = body_refresh["access_token"].as_str().unwrap();
    let claims = verify_access(&config, &signing, access, "uji-oa")
        .expect("access token hasil refresh harus sah");
    assert_eq!(claims.typ, "user");
    assert_eq!(claims.sub, user_id.to_string());
    assert_eq!(claims.scope, vec!["user:read".to_string()]);

    let (status_lama, body_lama, _) = send_token(
        &app,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", &fixture.client_id),
            ("refresh_token", &refresh_lama),
        ],
        None,
    )
    .await;
    assert_eq!(status_lama, StatusCode::BAD_REQUEST);
    assert_eq!(body_lama["error"], "invalid_grant");
}

#[sqlx::test]
async fn client_credentials_masih_berjalan(pool: PgPool) {
    // Regresi: grant lama tidak boleh ikut berubah karena dua grant baru.
    let fixture = fixture_app(&pool, "uji-m2m-oa", AppKind::Service, CALLBACK).await;
    let app = build_app(test_state(pool));

    let (status, body, cache_control) = send_token(
        &app,
        &[("grant_type", "client_credentials")],
        Some((&fixture.client_id, &fixture.secret)),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "client_credentials harus 200: {body}"
    );
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["scope"], "");
    assert!(
        body.get("refresh_token").is_none(),
        "grant mesin tidak menerbitkan refresh token"
    );
    assert_eq!(cache_control.as_deref(), Some("no-store"));
    assert_eq!(
        json!(body["expires_in"]),
        json!(fixture.app.access_ttl_secs)
    );
}
