//! Test layar RBAC dan audit, plus kartu ringkasan dashboard.
//!
//! Yang diuji lewat `build_app` adalah jalur HTTP sungguhan: penegakan registry,
//! CSRF, guard eskalasi di lapisan domain, dan bentuk HTML yang dipakai pembaca
//! layar (label, caption, aria-label). Test tidak memeriksa warna atau tata
//! letak — itu urusan template, bukan kontrak.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::BodyExt;
use sanca::auth::keys::SigningKey;
use sanca::auth::password::hash_password;
use sanca::config::{Config, Environment, LogFormat};
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
/// Role sistem dari migrasi seed.
const SUPERADMIN_ROLE_ID: &str = "0192f3a4-5b6c-7d8e-9f01-234567890abd";
/// Password fixture.
const PASSWORD: &str = "password-uji-yang-panjang";

fn pepper() -> String {
    STANDARD.encode([7u8; 32])
}

fn config() -> Config {
    Config {
        iam_bind: "127.0.0.1:0".into(),
        environment: Environment::Dev,
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

fn app(pool: PgPool) -> Router {
    let config = config();
    let signing = SigningKey::load_or_generate(&config).expect("gagal membuat signing key test");
    build_app(AppState::new(pool, config, signing))
}

/// Isi tabel permission dari registry, seperti yang dilakukan startup.
async fn sync_permissions(pool: &PgPool) {
    rbac_sync::sync(pool)
        .await
        .expect("sync permission gagal di fixture");
}

/// Buat user aktif dengan satu role di app core berisi permission yang diminta.
/// Mengembalikan (user_id, role_id).
async fn fixture_user(
    pool: &PgPool,
    email: &str,
    role_key: &str,
    permissions: &[&str],
) -> (Uuid, Uuid) {
    let hash = hash_password(PASSWORD, &SecretString::from(pepper())).expect("hash password gagal");
    let user = users::insert(pool, email, &hash, "Penguji")
        .await
        .expect("gagal membuat user fixture");

    let role_id = buat_role(pool, role_key).await;

    for key in permissions {
        let permission_id: Uuid =
            sqlx::query_scalar("SELECT id FROM permissions WHERE app_id = $1 AND key = $2")
                .bind(Uuid::parse_str(CORE_APP_ID).unwrap())
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

    (user.id, role_id)
}

/// Role biasa di app core, tanpa permission.
async fn buat_role(pool: &PgPool, key: &str) -> Uuid {
    let role_id = Uuid::now_v7();

    sqlx::query("INSERT INTO roles (id, app_id, key, name) VALUES ($1, $2, $3, $4)")
        .bind(role_id)
        .bind(Uuid::parse_str(CORE_APP_ID).unwrap())
        .bind(key)
        .bind(format!("Role {key}"))
        .execute(pool)
        .await
        .expect("gagal membuat role fixture");

    role_id
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

/// Access token lewat API, supaya test fokus pada layar console.
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

/// Token CSRF dari halaman mana pun yang dirender dengan cookie sesi.
async fn csrf_token(app: &Router, access: &str, uri: &str) -> String {
    let halaman = get(app, uri, access).await;
    assert_eq!(halaman.status(), StatusCode::OK, "halaman {uri} harus 200");
    set_cookie(&halaman, csrf::COOKIE_NAME).expect("cookie sanca_csrf wajib ada")
}

/// Jumlah permission yang terpasang di satu role.
async fn permission_count(pool: &PgPool, role_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM role_permissions WHERE role_id = $1")
        .bind(role_id)
        .fetch_one(pool)
        .await
        .expect("gagal menghitung permission role")
}

#[sqlx::test]
async fn matriks_200_dan_role_sistem_tidak_bisa_dicentang(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "pembaca@example.com",
        "pembaca",
        &["role:read", "role:write"],
    )
    .await;

    let app = app(pool);
    let access = access_token(&app, "pembaca@example.com").await;

    let response = get(&app, "/console/rbac", &access).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_text(response).await;
    assert!(body.contains("Peran &amp; izin"), "judul halaman wajib ada");
    assert!(
        body.contains("role:read"),
        "katalog permission wajib tampil"
    );
    assert!(
        body.contains("form-perm_"),
        "setiap kolom role punya form sendiri"
    );
    assert!(
        body.contains("sistem, tidak bisa diubah"),
        "role sistem harus diberi label beku"
    );

    // Checkbox pada kolom superadmin harus disabled.
    let superadmin = Uuid::parse_str(SUPERADMIN_ROLE_ID).unwrap();
    let needle = format!("name=\"perm_{superadmin}\"");
    let start = body
        .find(&needle)
        .unwrap_or_else(|| panic!("checkbox kolom superadmin tidak ada"));
    let open = body[start..].find('>').expect("tag input tertutup") + start;
    let tag = &body[start..open];
    assert!(
        tag.contains("disabled"),
        "checkbox role is_system wajib disabled: {tag}"
    );
}

#[sqlx::test]
async fn matriks_tanpa_role_read_ditolak_403(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "tanpa-izin@example.com", "kosong", &[]).await;

    let app = app(pool);
    let access = access_token(&app, "tanpa-izin@example.com").await;

    let response = get(&app, "/console/rbac", &access).await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "tanpa role:read registry harus menolak"
    );
}

#[sqlx::test]
async fn simpan_permission_role_biasa_303_dan_db_berubah(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis@example.com",
        "penulis",
        &["role:read", "role:write"],
    )
    .await;

    let target = buat_role(&pool, "uji-edit").await;
    assert_eq!(permission_count(&pool, target).await, 0);

    let app = app(pool.clone());
    let access = access_token(&app, "penulis@example.com").await;
    let token = csrf_token(&app, &access, "/console/rbac").await;

    let response = post_form(
        &app,
        &format!("/console/rbac/roles/{target}/permissions"),
        &access,
        &token,
        &format!("permissions=role:read&permissions=role:write&_csrf={token}"),
    )
    .await;

    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "penyimpanan yang berhasil harus 303"
    );
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/console/rbac?ok=izin-role-tersimpan")
    );
    assert_eq!(
        permission_count(&pool, target).await,
        2,
        "dua permission harus benar-benar tersimpan di database"
    );

    // Body kosong = cabut semua, tetap satu role sekali simpan.
    let kosong = post_form(
        &app,
        &format!("/console/rbac/roles/{target}/permissions"),
        &access,
        &token,
        &format!("_csrf={token}"),
    )
    .await;
    assert_eq!(kosong.status(), StatusCode::SEE_OTHER);
    assert_eq!(permission_count(&pool, target).await, 0);
}

#[sqlx::test]
async fn simpan_permission_role_sistem_ditolak_403(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis@example.com",
        "penulis",
        &["role:read", "role:write"],
    )
    .await;

    let app = app(pool.clone());
    let access = access_token(&app, "penulis@example.com").await;
    let token = csrf_token(&app, &access, "/console/rbac").await;

    let response = post_form(
        &app,
        &format!("/console/rbac/roles/{SUPERADMIN_ROLE_ID}/permissions"),
        &access,
        &token,
        &format!("permissions=role:read&_csrf={token}"),
    )
    .await;

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "role is_system beku untuk semua pemanggil"
    );
    assert_eq!(
        permission_count(&pool, Uuid::parse_str(SUPERADMIN_ROLE_ID).unwrap()).await,
        0,
        "penolakan tidak boleh menyisakan perubahan"
    );
}

#[sqlx::test]
async fn non_superadmin_tidak_boleh_memberi_di_luar_scope(pool: PgPool) {
    sync_permissions(&pool).await;
    // Pemegang role:write saja, tanpa user:write.
    fixture_user(
        &pool,
        "penulis@example.com",
        "penulis",
        &["role:read", "role:write"],
    )
    .await;

    let target = buat_role(&pool, "uji-eskalasi").await;

    let app = app(pool.clone());
    let access = access_token(&app, "penulis@example.com").await;
    let token = csrf_token(&app, &access, "/console/rbac").await;

    let response = post_form(
        &app,
        &format!("/console/rbac/roles/{target}/permissions"),
        &access,
        &token,
        &format!("permissions=user:write&_csrf={token}"),
    )
    .await;

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "guard domain harus menolak pemberian izin di luar scope pemanggil"
    );
    assert_eq!(
        permission_count(&pool, target).await,
        0,
        "tidak ada permission yang boleh tersimpan saat ditolak"
    );
}

#[sqlx::test]
async fn simpan_tanpa_csrf_ditolak_403(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "penulis@example.com",
        "penulis",
        &["role:read", "role:write"],
    )
    .await;

    let target = buat_role(&pool, "uji-csrf").await;

    let app = app(pool.clone());
    let access = access_token(&app, "penulis@example.com").await;

    // Cookie berisi token asli, body berisi token lain: harus ditolak.
    let token = csrf_token(&app, &access, "/console/rbac").await;

    let response = post_form(
        &app,
        &format!("/console/rbac/roles/{target}/permissions"),
        &access,
        &token,
        "permissions=role:read&_csrf=token-palsu",
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(permission_count(&pool, target).await, 0);
}

#[sqlx::test]
async fn audit_200_empty_state_lalu_filter_app_bekerja(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "auditor@example.com", "auditor", &["audit:read"]).await;

    let app = app(pool.clone());
    let access = access_token(&app, "auditor@example.com").await;

    let kosong = get(&app, "/console/audit", &access).await;
    assert_eq!(kosong.status(), StatusCode::OK);
    let body = body_text(kosong).await;
    assert!(
        body.contains("Belum ada aktivitas tercatat"),
        "empty state wajib jelas saat tabel kosong"
    );
    assert!(body.contains("caption"), "tabel wajib punya caption");

    for (slug, action) in [
        ("core", "role.izin.ubah"),
        ("salak", "user.masuk"),
        ("kelapa", "app.dibuat"),
    ] {
        sqlx::query(
            r#"
            INSERT INTO audit_events
                (app_slug, actor_type, action, method, path, status_code, request_id)
            VALUES ($1, 'user', $2, 'POST', '/api/uji', 200, $3)
            "#,
        )
        .bind(slug)
        .bind(action)
        .bind(format!("req-{slug}"))
        .execute(&pool)
        .await
        .expect("gagal menyisipkan audit fixture");
    }

    let semua = get(&app, "/console/audit", &access).await;
    assert_eq!(semua.status(), StatusCode::OK);
    let body = body_text(semua).await;
    assert!(body.contains("role.izin.ubah"));
    assert!(body.contains("user.masuk"));
    assert!(body.contains("app.dibuat"));

    let filter = get(&app, "/console/audit?app_slug=salak", &access).await;
    assert_eq!(filter.status(), StatusCode::OK);
    let body = body_text(filter).await;
    assert!(body.contains("user.masuk"), "baris app salak harus tampil");
    assert!(body.contains("req-salak"));
    assert!(
        !body.contains("app.dibuat"),
        "baris app lain tidak boleh ikut tampil"
    );
    assert!(!body.contains("role.izin.ubah"));

    // Rentang tanggal yang tidak mencakup hari ini tidak boleh memuat baris.
    let lampau = get(
        &app,
        "/console/audit?dari=2020-01-01&sampai=2020-01-02",
        &access,
    )
    .await;
    assert_eq!(lampau.status(), StatusCode::OK);
    let body = body_text(lampau).await;
    assert!(body.contains("Tidak ada aktivitas yang cocok"));
    assert!(!body.contains("user.masuk"));
}

#[sqlx::test]
async fn audit_tanpa_permission_ditolak_403(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "tanpa-izin@example.com", "kosong", &[]).await;

    let app = app(pool);
    let access = access_token(&app, "tanpa-izin@example.com").await;

    assert_eq!(
        get(&app, "/console/audit", &access).await.status(),
        StatusCode::FORBIDDEN
    );
}

#[sqlx::test]
async fn dashboard_menampilkan_angka_yang_sama_dengan_database(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "pembaca@example.com", "pembaca", &["role:read"]).await;

    let app = app(pool.clone());
    let access = access_token(&app, "pembaca@example.com").await;

    // Counter yang stabil dihitung sebelum request, plus nilai minimum audit.
    // Audit dipakai sebagai batas bawah saja: request GET /console ini sendiri
    // ikut dicatat middleware audit, jadi angkanya pasti bertambah sedikit
    // selama request berjalan dan tidak boleh di-assert persis.
    let sebelum = sqlx::query!(
        r#"
        SELECT (SELECT count(*) FROM users WHERE status = 'active') AS "users_active!",
               (SELECT count(*) FROM apps) AS "apps_count!",
               (SELECT count(*) FROM roles) AS "roles_count!",
               (SELECT count(*) FROM permissions) AS "permissions_count!",
               (SELECT count(*) FROM audit_events
                WHERE occurred_at > now() - interval '24 hours') AS "audit_min!"
        "#
    )
    .fetch_one(&pool)
    .await
    .expect("gagal menghitung ekspektasi dashboard");

    // Ambil isi halaman lebih dulu, baru hitung sesi dari database sesudahnya.
    let response = get(&app, "/console", &access).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;

    let sesi_aktif: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*) FROM sessions
        WHERE revoked_at IS NULL AND expires_at > now()
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("gagal menghitung sesi aktif setelah request");

    for (label, value) in [
        ("pengguna aktif", sebelum.users_active),
        ("aplikasi", sebelum.apps_count),
        ("role", sebelum.roles_count),
        ("permission", sebelum.permissions_count),
        ("sesi", sesi_aktif),
    ] {
        assert!(
            body.contains(&format!("tabular\">{value}</p>")),
            "kartu {label} harus menampilkan {value}"
        );
    }

    // Kartu audit dibaca langsung dari HTML: harus berupa bilangan bulat, tidak
    // boleh lebih kecil dari hitungan sebelum request, dan tidak wajar kalau
    // melonjak jauh hanya karena satu request ini.
    let audit_min = sebelum.audit_min;
    let audit_card = angka_kartu(&body, "Audit 24 jam").unwrap_or_else(|| {
        panic!("kartu Audit 24 jam harus memuat angka, minimum yang diharapkan {audit_min}")
    });
    assert!(
        audit_card >= audit_min,
        "kartu audit menampilkan {audit_card}, tidak boleh di bawah {audit_min}"
    );
    assert!(
        audit_card <= audit_min + 10,
        "kartu audit melonjak ke {audit_card}, padahal sebelum request hanya {audit_min}"
    );

    assert!(
        body.contains("href=\"/console/rbac\""),
        "tautan cepat rbac muncul karena pemanggil punya role:read"
    );
    assert!(
        !body.contains("href=\"/console/audit\""),
        "tautan audit tidak boleh muncul tanpa audit:read"
    );
}

/// Ambil angka pada kartu dashboard yang berlabel `label`. Nilai kartu dirender
/// sebagai `<p class="... tabular">ANGKA</p>` tepat setelah paragraf label.
fn angka_kartu(body: &str, label: &str) -> Option<i64> {
    let posisi_label = body.find(label)?;
    let sesudah = &body[posisi_label..];
    let awal = sesudah.find("tabular\">")? + "tabular\">".len();
    let sisa = &sesudah[awal..];
    let akhir = sisa.find('<')?;
    sisa[..akhir].trim().parse().ok()
}

#[sqlx::test]
async fn matriks_memenuhi_syarat_aksesibilitas_dasar(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(
        &pool,
        "pembaca@example.com",
        "pembaca",
        &["role:read", "role:write"],
    )
    .await;

    let app = app(pool);
    let access = access_token(&app, "pembaca@example.com").await;

    let body = body_text(get(&app, "/console/rbac", &access).await).await;

    assert!(
        body.contains("aria-label=\"Matriks izin per role di app core\""),
        "tabel matriks wajib punya aria-label"
    );
    assert!(
        body.contains("<h1") && body.matches("<h1").count() == 1,
        "halaman wajib punya tepat satu h1"
    );

    // Setiap checkbox matriks harus punya id yang dipakai sebuah <label for>.
    let mut ids = Vec::new();
    let mut rest = body.as_str();
    while let Some(pos) = rest.find("name=\"perm_") {
        let before = &rest[..pos];
        let id_pos = before.rfind("id=\"").expect("checkbox tanpa id");
        let after_quote = &before[id_pos + 4..];
        let end = after_quote.find('"').expect("id tidak tertutup");
        ids.push(after_quote[..end].to_string());
        rest = &rest[pos + 10..];
    }

    assert!(!ids.is_empty(), "harus ada checkbox matriks");
    for id in ids {
        assert!(
            body.contains(&format!("for=\"{id}\"")),
            "checkbox {id} tidak punya <label for>"
        );
    }
}

#[sqlx::test]
async fn nav_hanya_memuat_menu_yang_diizinkan(pool: PgPool) {
    sync_permissions(&pool).await;
    fixture_user(&pool, "tanpa-izin@example.com", "kosong", &[]).await;
    fixture_user(&pool, "rbac-saja@example.com", "rbac", &["role:read"]).await;

    let app = app(pool);
    let tanpa = access_token(&app, "tanpa-izin@example.com").await;
    let body = body_text(get(&app, "/console", &tanpa).await).await;
    assert!(
        !body.contains("/console/rbac"),
        "tanpa role:read menu RBAC tidak boleh dirender"
    );
    assert!(
        !body.contains("/console/audit"),
        "tanpa audit:read menu audit tidak boleh dirender"
    );

    let rbac_saja = access_token(&app, "rbac-saja@example.com").await;
    let body = body_text(get(&app, "/console", &rbac_saja).await).await;
    assert!(body.contains("/console/rbac"), "menu RBAC harus muncul");
    assert!(
        !body.contains("/console/audit"),
        "menu audit tetap butuh audit:read"
    );
}
