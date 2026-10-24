//! Resolusi role dan scope: apa yang dimiliki seorang user di satu app.

use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

/// Beri `user_id` role `superadmin` milik app `core`.
///
/// Dipanggil dari jalur pembuatan user superadmin supaya token-nya benar-benar
/// memuat klaim `role`, bukan hanya flag `users.is_superadmin`. Wajib berjalan
/// di transaksi yang sama dengan insert user.
///
/// Mengembalikan `false` kalau app `core` atau role `superadmin` tidak ada
/// (seed belum dijalankan); pemanggil wajib membatalkan transaksi.
pub async fn assign_system_superadmin(
    conn: &mut PgConnection,
    user_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let role_id = sqlx::query_scalar!(
        r#"
        SELECT r.id
        FROM roles r
        JOIN apps a ON a.id = r.app_id
        WHERE a.slug = 'core'
          AND r.key = 'superadmin'
        "#
    )
    .fetch_optional(&mut *conn)
    .await?;

    let Some(role_id) = role_id else {
        return Ok(false);
    };

    sqlx::query!(
        r#"
        INSERT INTO user_roles (user_id, role_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        "#,
        user_id,
        role_id,
    )
    .execute(conn)
    .await?;

    Ok(true)
}

/// Key role milik `user_id` di `app_id` saja, unik dan terurut.
///
/// Dipakai untuk klaim `role` pada access token. Role app lain tidak pernah ikut.
pub async fn resolve_roles(
    pool: &PgPool,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        SELECT DISTINCT r.key
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id = $1
          AND r.app_id = $2
        ORDER BY 1
        "#,
        user_id,
        app_id,
    )
    .fetch_all(pool)
    .await
}

/// Kumpulan key permission milik `user_id` di `app_id` saja, unik dan terurut.
/// Role milik app lain tidak pernah bocor ke hasil.
pub async fn resolve_scope(
    pool: &PgPool,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        SELECT DISTINCT p.key
        FROM user_roles ur
        JOIN roles r            ON r.id = ur.role_id
        JOIN role_permissions rp ON rp.role_id = r.id
        JOIN permissions p      ON p.id = rp.permission_id
        WHERE ur.user_id = $1
          AND r.app_id = $2
          AND p.app_id = $2
        ORDER BY 1
        "#,
        user_id,
        app_id,
    )
    .fetch_all(pool)
    .await
}
