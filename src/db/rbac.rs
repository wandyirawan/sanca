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

/// Satu baris role apa adanya, dipakai lapisan domain untuk memutuskan boleh
/// atau tidaknya role diubah.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Role {
    pub id: Uuid,
    pub app_id: Uuid,
    pub key: String,
    pub name: String,
    pub description: String,
    pub is_system: bool,
}

/// Ambil satu role lewat id. `None` berarti id itu tidak ada.
pub async fn role_by_id(pool: &PgPool, role_id: Uuid) -> Result<Option<Role>, sqlx::Error> {
    sqlx::query_as!(
        Role,
        r#"
        SELECT id, app_id, key, name, description, is_system
        FROM roles
        WHERE id = $1
        "#,
        role_id,
    )
    .fetch_optional(pool)
    .await
}

/// Key permission yang saat ini terpasang di satu role, terurut.
pub async fn permissions_of_role(pool: &PgPool, role_id: Uuid) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        SELECT p.key
        FROM role_permissions rp
        JOIN permissions p ON p.id = rp.permission_id
        WHERE rp.role_id = $1
        ORDER BY 1
        "#,
        role_id,
    )
    .fetch_all(pool)
    .await
}

/// Id permission yang terpasang di satu role, terurut.
pub async fn role_permission_ids(pool: &PgPool, role_id: Uuid) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        SELECT rp.permission_id
        FROM role_permissions rp
        WHERE rp.role_id = $1
        ORDER BY 1
        "#,
        role_id,
    )
    .fetch_all(pool)
    .await
}

/// Ganti seluruh isi permission sebuah role dengan daftar `keys` (set eksak).
///
/// Hapus lalu insert dijalankan dalam satu transaksi supaya role tidak pernah
/// terlihat setengah kosong oleh request lain. Hanya permission milik app yang
/// sama dengan role yang bisa masuk; key asing diabaikan di sini dan sudah
/// ditolak lebih awal oleh lapisan domain.
///
/// Mengembalikan jumlah baris yang benar-benar terpasang.
pub async fn set_role_permissions(
    pool: &PgPool,
    role_id: Uuid,
    keys: &[String],
) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query!("DELETE FROM role_permissions WHERE role_id = $1", role_id)
        .execute(&mut *tx)
        .await?;

    let inserted = sqlx::query!(
        r#"
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT $1, p.id
        FROM permissions p
        JOIN roles r ON r.app_id = p.app_id
        WHERE r.id = $1
          AND p.key = ANY($2)
        ON CONFLICT DO NOTHING
        "#,
        role_id,
        keys,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(inserted.rows_affected())
}

/// Tambahkan satu permission ke role. `false` berarti key itu tidak ada di app
/// yang sama atau sudah terpasang.
pub async fn add_role_permission(
    pool: &PgPool,
    role_id: Uuid,
    key: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        INSERT INTO role_permissions (role_id, permission_id)
        SELECT $1, p.id
        FROM permissions p
        JOIN roles r ON r.app_id = p.app_id
        WHERE r.id = $1
          AND p.key = $2
        ON CONFLICT DO NOTHING
        "#,
        role_id,
        key,
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Cabut satu permission dari role. `false` berarti tidak ada yang tercabut.
pub async fn remove_role_permission(
    pool: &PgPool,
    role_id: Uuid,
    key: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        DELETE FROM role_permissions rp
        USING permissions p, roles r
        WHERE rp.role_id = $1
          AND rp.permission_id = p.id
          AND r.id = rp.role_id
          AND r.app_id = p.app_id
          AND p.key = $2
        "#,
        role_id,
        key,
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Id permission berdasarkan key di satu app; `None` kalau key tidak terdaftar.
pub async fn permission_id_by_key(
    pool: &PgPool,
    app_id: Uuid,
    key: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    sqlx::query_scalar!(
        r#"
        SELECT id
        FROM permissions
        WHERE app_id = $1
          AND key = $2
        "#,
        app_id,
        key,
    )
    .fetch_optional(pool)
    .await
}

/// Beri `role_id` ke `user_id`; `granted_by` dicatat sebagai pemberi.
/// Pemberian ganda tidak menjadi error.
pub async fn assign_role(
    pool: &PgPool,
    user_id: Uuid,
    role_id: Uuid,
    granted_by: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        INSERT INTO user_roles (user_id, role_id, granted_by)
        VALUES ($1, $2, $3)
        ON CONFLICT DO NOTHING
        "#,
        user_id,
        role_id,
        granted_by,
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Cabut `role_id` dari `user_id`. `false` berarti user memang tidak punya role itu.
pub async fn unassign_role(
    pool: &PgPool,
    user_id: Uuid,
    role_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        DELETE FROM user_roles
        WHERE user_id = $1
          AND role_id = $2
        "#,
        user_id,
        role_id,
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Semua role milik satu user, lintas app, terurut slug app lalu key role.
pub async fn roles_of_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<Role>, sqlx::Error> {
    sqlx::query_as!(
        Role,
        r#"
        SELECT r.id, r.app_id, r.key, r.name, r.description, r.is_system
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        JOIN apps a  ON a.id = r.app_id
        WHERE ur.user_id = $1
        ORDER BY a.slug, r.key
        "#,
        user_id,
    )
    .fetch_all(pool)
    .await
}

/// Hapus role. Baris `user_roles` dan `role_permissions` ikut terhapus lewat
/// ON DELETE CASCADE.
pub async fn delete_role(pool: &PgPool, role_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!("DELETE FROM roles WHERE id = $1", role_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
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
