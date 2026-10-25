//! Test integrasi untuk empat modul db baru: apps, sessions, audit, keys.
//!
//! Setiap test mendapat database sementara sendiri dari `#[sqlx::test]`, dan
//! migrasi dijalankan otomatis di sana. Jadi data antar test tidak bertabrakan.

use sanca::db::{apps, audit, keys, sessions};
use serde_json::json;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Bikin app baru sebagai fixture, slug unik per test.
async fn fixture_app(pool: &PgPool, slug: &str) -> Uuid {
    apps::insert(pool, slug, "App Uji", apps::AppKind::Service, "")
        .await
        .expect("gagal membuat app fixture")
        .id
}

/// Bikin user minimal sebagai fixture (email unik per test).
async fn fixture_user(pool: &PgPool, email: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO users (id, email, password_hash, display_name)
        VALUES ($1, $2::citext, 'bukan-hash-nyata', 'User Uji')
        "#,
    )
    .bind(id)
    .bind(email)
    .execute(pool)
    .await
    .expect("gagal membuat user fixture");
    id
}

#[sqlx::test]
async fn apps_insert_lookup_dan_revoke_credential(pool: PgPool) {
    let app = apps::insert(&pool, "uji-apps", "Aplikasi Uji", apps::AppKind::Spa, "")
        .await
        .expect("insert app gagal");
    assert_eq!(app.slug, "uji-apps");
    assert_eq!(app.kind, apps::AppKind::Spa);
    assert!(app.is_active);
    assert!(app.redirect_uris.is_empty());

    let by_slug = apps::by_slug(&pool, "uji-apps")
        .await
        .expect("by_slug error")
        .expect("app tidak ketemu lewat slug");
    assert_eq!(by_slug.id, app.id);

    let by_id = apps::by_id(&pool, app.id)
        .await
        .expect("by_id error")
        .expect("app tidak ketemu lewat id");
    assert_eq!(by_id.slug, "uji-apps");

    apps::create_credential(&pool, app.id, "client-uji-1", "hash-rahasia")
        .await
        .expect("insert credential gagal");

    let hidup = apps::credential_by_client_id(&pool, "client-uji-1")
        .await
        .expect("query credential error")
        .expect("credential hidup seharusnya ketemu");
    assert_eq!(hidup.app_id, app.id);

    apps::revoke_credentials(&pool, app.id)
        .await
        .expect("revoke credential gagal");

    let setelah_revoke = apps::credential_by_client_id(&pool, "client-uji-1")
        .await
        .expect("query credential error");
    assert!(
        setelah_revoke.is_none(),
        "credential yang dicabut harus tidak ketemu"
    );
}

#[sqlx::test]
async fn sessions_insert_lookup_dan_revoke(pool: PgPool) {
    let user_id = fixture_user(&pool, "sesi@contoh.test").await;
    let app_id = fixture_app(&pool, "uji-sesi").await;
    let kedaluwarsa = OffsetDateTime::now_utc() + time::Duration::days(30);

    let id = sessions::insert(
        &pool,
        user_id,
        app_id,
        "hash-refresh-1",
        kedaluwarsa,
        "uji-agent/1.0",
        Some("127.0.0.1"),
    )
    .await
    .expect("insert sesi gagal");

    let sesi = sessions::by_refresh_hash(&pool, "hash-refresh-1")
        .await
        .expect("by_refresh_hash error")
        .expect("sesi hidup seharusnya ketemu");
    assert_eq!(sesi.id, id);
    assert_eq!(sesi.app_id, app_id);

    sessions::revoke(&pool, id)
        .await
        .expect("revoke sesi gagal");

    let setelah_revoke = sessions::by_refresh_hash(&pool, "hash-refresh-1")
        .await
        .expect("by_refresh_hash error");
    assert!(
        setelah_revoke.is_none(),
        "sesi yang dicabut harus tidak ketemu"
    );

    // Sesi yang lewat masa berlaku juga tidak boleh dikembalikan, walau belum dicabut.
    sessions::insert(
        &pool,
        user_id,
        app_id,
        "hash-refresh-kedaluwarsa",
        OffsetDateTime::now_utc() - time::Duration::minutes(1),
        "uji-agent/1.0",
        None,
    )
    .await
    .expect("insert sesi kedaluwarsa gagal");

    assert!(
        sessions::by_refresh_hash(&pool, "hash-refresh-kedaluwarsa")
            .await
            .expect("by_refresh_hash error")
            .is_none(),
        "sesi kedaluwarsa harus tidak ketemu"
    );

    // revoke_all_for_user_app menyapu semua sesi hidup user di app itu.
    let kedua = sessions::insert(
        &pool,
        user_id,
        app_id,
        "hash-refresh-2",
        kedaluwarsa,
        "uji-agent/1.0",
        None,
    )
    .await
    .expect("insert sesi kedua gagal");
    sessions::revoke_all_for_user_app(&pool, user_id, app_id)
        .await
        .expect("revoke_all gagal");
    let sisa = sessions::by_refresh_hash(&pool, "hash-refresh-2")
        .await
        .expect("by_refresh_hash error");
    assert!(sisa.is_none(), "sesi {kedua} seharusnya sudah dicabut");
}

#[sqlx::test]
async fn audit_insert_dan_filter_app(pool: PgPool) {
    let app_a = fixture_app(&pool, "uji-audit-a").await;
    let _app_b = fixture_app(&pool, "uji-audit-b").await;
    let user_id = fixture_user(&pool, "audit@contoh.test").await;

    let buat = |slug: &'static str, app_id: Option<Uuid>, action: &'static str, kode: i16| {
        let metadata = json!({ "catatan": action });
        async move {
            audit::NewEvent {
                app_id,
                app_slug: slug,
                actor_type: audit::ActorType::User,
                actor_user_id: Some(user_id),
                action,
                method: "POST",
                path: "/api/auth/login",
                status_code: Some(kode),
                request_id: "req-uji",
                ip: None,
                user_agent: "uji",
                metadata,
            }
        }
    };

    let ev_a = audit::insert(&pool, &buat("uji-audit-a", Some(app_a), "login", 200).await)
        .await
        .expect("insert event a gagal");
    audit::insert(&pool, &buat("uji-audit-b", None, "logout", 204).await)
        .await
        .expect("insert event b gagal");
    let ev_a2 = audit::insert(
        &pool,
        &buat("uji-audit-a", Some(app_a), "refresh", 200).await,
    )
    .await
    .expect("insert event a2 gagal");

    let semua = audit::list(&pool, None, None, 50, 0)
        .await
        .expect("list tanpa filter gagal");
    assert_eq!(semua.len(), 3, "tanpa filter semua event harus terlihat");

    let hanya_a = audit::list(&pool, Some("uji-audit-a"), None, 50, 0)
        .await
        .expect("list dengan filter app gagal");
    assert_eq!(hanya_a.len(), 2, "filter app harus menyaring app lain");
    assert!(hanya_a.iter().all(|e| e.app_slug == "uji-audit-a"));
    let id_terkumpul: Vec<i64> = hanya_a.iter().map(|e| e.id).collect();
    assert!(id_terkumpul.contains(&ev_a));
    assert!(id_terkumpul.contains(&ev_a2));

    let per_actor = audit::list(&pool, None, Some(user_id), 50, 0)
        .await
        .expect("list dengan filter actor gagal");
    assert_eq!(per_actor.len(), 3);

    let tak_ada = audit::list(&pool, Some("app-tidak-ada"), None, 50, 0)
        .await
        .expect("list filter kosong gagal");
    assert!(tak_ada.is_empty());
}

#[sqlx::test]
async fn keys_insert_list_dan_retire(pool: PgPool) {
    keys::insert(
        &pool,
        "kid-1",
        "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----",
    )
    .await
    .expect("insert key 1 gagal");
    keys::insert(
        &pool,
        "kid-2",
        "-----BEGIN PUBLIC KEY-----\nBBB\n-----END PUBLIC KEY-----",
    )
    .await
    .expect("insert key 2 gagal");

    let aktif = keys::list_active(&pool).await.expect("list_active gagal");
    assert_eq!(aktif.len(), 2);
    assert!(aktif.iter().all(|k| k.alg == "RS256"));

    keys::retire(&pool, "kid-1").await.expect("retire gagal");

    let tersisa = keys::list_active(&pool).await.expect("list_active gagal");
    assert_eq!(tersisa.len(), 1);
    assert_eq!(tersisa[0].kid, "kid-2");
}
