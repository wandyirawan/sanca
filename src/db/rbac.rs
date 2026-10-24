//! Resolusi scope: daftar permission efektif seorang user di satu app.

use sqlx::PgPool;
use uuid::Uuid;

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
