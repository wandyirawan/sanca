//! Test skema dan dua query inti terhadap Postgres nyata. `#[sqlx::test]` membuat
//! database sementara sendiri lalu menjalankan seluruh migrasi.

use sanca::db::{rbac, users};
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test]
async fn migrasi_jalan_dan_seed_core_ada(pool: PgPool) -> sqlx::Result<()> {
    let jumlah_user: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&pool)
        .await?;
    assert_eq!(jumlah_user, 0, "database test harus mulai kosong");

    let (slug, kind, aktif): (String, String, bool) =
        sqlx::query_as("SELECT slug, kind::text, is_active FROM apps WHERE slug = 'core'")
            .fetch_one(&pool)
            .await?;
    assert_eq!(slug, "core");
    assert_eq!(kind, "web");
    assert!(aktif, "app core harus aktif");

    let role_sistem: bool = sqlx::query_scalar(
        "SELECT r.is_system FROM roles r JOIN apps a ON a.id = r.app_id
         WHERE a.slug = 'core' AND r.key = 'superadmin'",
    )
    .fetch_one(&pool)
    .await?;
    assert!(role_sistem, "role superadmin harus is_system = true");

    Ok(())
}

#[sqlx::test]
async fn insert_lalu_by_email_termasuk_beda_kapital(pool: PgPool) -> sqlx::Result<()> {
    let dibuat = users::insert(&pool, "Rani@Example.com", "$argon2id$dummy", "Rani").await?;
    assert_eq!(dibuat.email, "Rani@Example.com");
    assert_eq!(dibuat.status, users::UserStatus::Active);
    assert!(!dibuat.is_superadmin);
    assert_eq!(dibuat.token_version, 0);

    let ketemu = users::by_email(&pool, "rani@example.com")
        .await?
        .expect("email beda kapital harus tetap ketemu");
    assert_eq!(ketemu.id, dibuat.id);
    assert_eq!(ketemu.password_hash, "$argon2id$dummy");

    assert!(
        users::by_email(&pool, "tidak-ada@example.com")
            .await?
            .is_none(),
        "email asing tidak boleh menghasilkan user"
    );

    Ok(())
}

#[sqlx::test]
async fn resolve_scope_hanya_untuk_app_yang_diminta(pool: PgPool) -> sqlx::Result<()> {
    let app_a = Uuid::now_v7();
    let app_b = Uuid::now_v7();
    for (id, slug) in [(app_a, "salak"), (app_b, "kelapa")] {
        sqlx::query("INSERT INTO apps (id, slug, name) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(slug)
            .bind(slug)
            .execute(&pool)
            .await?;
    }

    let user = users::insert(&pool, "budi@example.com", "$argon2id$dummy", "Budi").await?;

    // App A: satu role dengan dua permission. App B: role lain, tidak diberikan ke user.
    let role_a = Uuid::now_v7();
    let role_b = Uuid::now_v7();
    sqlx::query("INSERT INTO roles (id, app_id, key, name) VALUES ($1, $2, 'editor', 'Editor')")
        .bind(role_a)
        .bind(app_a)
        .execute(&pool)
        .await?;
    sqlx::query("INSERT INTO roles (id, app_id, key, name) VALUES ($1, $2, 'viewer', 'Viewer')")
        .bind(role_b)
        .bind(app_b)
        .execute(&pool)
        .await?;

    let mut perm_a = Vec::new();
    for key in ["user:read", "user:write"] {
        let id = Uuid::now_v7();
        sqlx::query("INSERT INTO permissions (id, app_id, key, name) VALUES ($1, $2, $3, $3)")
            .bind(id)
            .bind(app_a)
            .bind(key)
            .execute(&pool)
            .await?;
        sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
            .bind(role_a)
            .bind(id)
            .execute(&pool)
            .await?;
        perm_a.push((id, key.to_string()));
    }

    let perm_b = Uuid::now_v7();
    sqlx::query("INSERT INTO permissions (id, app_id, key, name) VALUES ($1, $2, 'billing:read', 'billing:read')")
        .bind(perm_b)
        .bind(app_b)
        .execute(&pool)
        .await?;
    sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
        .bind(role_b)
        .bind(perm_b)
        .execute(&pool)
        .await?;

    // User hanya memegang role di app A.
    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(user.id)
        .bind(role_a)
        .execute(&pool)
        .await?;

    let scope_a = rbac::resolve_scope(&pool, user.id, app_a).await?;
    assert_eq!(
        scope_a,
        vec!["user:read".to_string(), "user:write".to_string()],
        "scope app A harus berisi permission app A, terurut"
    );

    let scope_b = rbac::resolve_scope(&pool, user.id, app_b).await?;
    assert!(scope_b.is_empty(), "user tidak punya role di app B");

    Ok(())
}
