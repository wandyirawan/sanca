//! Test route kesehatan. `build_app` sekarang butuh state, jadi test ini memakai
//! database sementara dan signing key dev seperti test transport lainnya.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use sanca::auth::keys::SigningKey;
use sanca::config::{Config, Environment, LogFormat};
use sanca::startup::build_app;
use sanca::state::AppState;
use secrecy::SecretString;
use sqlx::PgPool;
use tower::ServiceExt;

fn test_state(pool: PgPool) -> AppState {
    let config = Config {
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
        log_dir: std::env::temp_dir(),
    };
    let signing = SigningKey::load_or_generate(&config).expect("gagal membuat signing key test");
    AppState::new(pool, config, signing)
}

#[sqlx::test]
async fn healthz_returns_200_ok(pool: PgPool) {
    let app = build_app(test_state(pool));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}
