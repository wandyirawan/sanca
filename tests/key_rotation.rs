//! Test rotasi signing key: keyset multi-kunci, `rotate`, dan `retire`.
//!
//! Setiap test memakai direktori kunci sendiri di `temp_dir`, jadi file PEM di
//! `~/.config/sanca/keys` tidak pernah tersentuh. Test yang butuh database
//! memakai `#[sqlx::test]`, yang membuat database sementara per test.

use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD};
use sanca::auth::jwt::{self, Claims, JwtError};
use sanca::auth::keys::{self, KeyError, KeySet, SigningKey};
use sanca::config::{Config, Environment, LogFormat};
use sanca::db::keys as db_keys;
use secrecy::SecretString;
use sqlx::PgPool;

/// Direktori kunci khusus satu test, selalu mulai kosong.
fn dir_uji(nama: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sanca-rotasi-{}-{nama}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("buat direktori kunci uji");
    dir
}

/// Config dev dengan direktori kunci dan `kid` yang ditentukan test.
fn config_uji(dir: &Path, kid: &str) -> Config {
    Config {
        iam_bind: "127.0.0.1:0".into(),
        environment: Environment::Dev,
        log_format: LogFormat::Pretty,
        iam_public_url: "https://iam.test".into(),
        jwt_kid: kid.into(),
        jwt_private_key_pem: None,
        jwt_private_key_path: None,
        sanca_key_dir: Some(dir.to_path_buf()),
        argon2_pepper: SecretString::from(STANDARD.encode([7u8; 32])),
        argon2_pepper_version: 1,
        client_secret_pepper: SecretString::from(STANDARD.encode([9u8; 32])),
        log_dir: std::env::temp_dir(),
    }
}

fn claims(aud: &str) -> Claims {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    Claims {
        iss: "https://iam.test".into(),
        sub: "0199c0de-0000-7000-8000-000000000001".into(),
        aud: aud.into(),
        azp: "0199c0de-0000-7000-8000-000000000002".into(),
        sid: "0199c0de-0000-7000-8000-000000000003".into(),
        typ: "user".into(),
        role: vec!["admin".into()],
        scope: vec!["user:read".into()],
        tv: 0,
        jti: "0199c0de-0000-7000-8000-000000000004".into(),
        iat: now,
        exp: now + 900,
    }
}

/// Daftar `kid` di payload JWKS, urut sesuai yang dipublikasikan.
fn kid_di_jwks(keyset: &KeySet) -> Vec<String> {
    keyset.jwks_json()["keys"]
        .as_array()
        .expect("keys harus array")
        .iter()
        .map(|key| key["kid"].as_str().expect("kid harus string").to_string())
        .collect()
}

/// `kid` di header token, bukan dari klaim.
fn kid_token(token: &str) -> String {
    jsonwebtoken::decode_header(token)
        .expect("header token")
        .kid
        .expect("token wajib punya kid")
}

#[test]
fn keyset_memuat_semua_file_pem_dan_jwks_berisi_semua_kid() {
    let dir = dir_uji("dua-kunci");

    let mut config = config_uji(&dir, "kunci-a");
    SigningKey::load_or_generate(&config).expect("kunci a");
    config.jwt_kid = "kunci-b".into();
    SigningKey::load_or_generate(&config).expect("kunci b");

    let keyset = KeySet::load(&config, &[], &[]).expect("muat keyset");

    assert!(keyset.verifier("kunci-a").is_some(), "kunci a harus hidup");
    assert!(keyset.verifier("kunci-b").is_some(), "kunci b harus hidup");
    assert_eq!(keyset.kid(), "kunci-b", "kunci aktif dari config");

    let kid = kid_di_jwks(&keyset);
    assert_eq!(kid.len(), 2, "JWKS memuat dua kunci hidup: {kid:?}");
    assert!(kid.contains(&"kunci-a".to_string()));
    assert!(kid.contains(&"kunci-b".to_string()));

    // Kunci aktif selalu di urutan pertama supaya verifier gampang memilih.
    assert_eq!(kid[0], "kunci-b");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn token_kunci_lama_tetap_valid_setelah_kunci_baru_aktif() {
    let dir = dir_uji("token-lama");

    let mut config = config_uji(&dir, "kunci-a");
    let kunci_a = SigningKey::load_or_generate(&config).expect("kunci a");
    let token_a = jwt::sign_access(&KeySet::from_signing_key(kunci_a), &claims("core"))
        .expect("tandatangani dengan kunci a");
    assert_eq!(kid_token(&token_a), "kunci-a");

    config.jwt_kid = "kunci-b".into();
    SigningKey::load_or_generate(&config).expect("kunci b");

    // Kunci aktif sekarang B, tetapi token yang ditandatangani A tetap sah
    // karena A masih hidup dan masih dipublikasikan.
    let keyset = KeySet::load(&config, &[], &[]).expect("muat keyset");
    assert_eq!(keyset.kid(), "kunci-b");

    let claims = jwt::verify_access(&config, &keyset, &token_a, "core").expect("token lama sah");
    assert_eq!(claims.aud, "core");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn kunci_yang_sudah_hilang_menghasilkan_unknown_kid() {
    let dir = dir_uji("kunci-hilang");

    let mut config = config_uji(&dir, "kunci-a");
    let kunci_a = SigningKey::load_or_generate(&config).expect("kunci a");
    let token_a = jwt::sign_access(&KeySet::from_signing_key(kunci_a), &claims("core"))
        .expect("tandatangani dengan kunci a");

    config.jwt_kid = "kunci-b".into();
    SigningKey::load_or_generate(&config).expect("kunci b");

    // Kunci A dipensiunkan: filenya hilang, jadi tidak ada verifier untuk kid itu.
    std::fs::remove_file(dir.join("kunci-a.pem")).expect("hapus kunci a");
    let keyset = KeySet::load(&config, &[], &[]).expect("muat keyset");

    assert!(keyset.verifier("kunci-a").is_none());
    assert_eq!(
        jwt::verify_access(&config, &keyset, &token_a, "core").unwrap_err(),
        JwtError::UnknownKid
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn kid_palsu_ditolak_sebelum_signature() {
    let dir = dir_uji("kid-palsu");

    let config = config_uji(&dir, "kunci-a");
    let kunci_a = SigningKey::load_or_generate(&config).expect("kunci a");
    let keyset = KeySet::load(&config, &[], &[]).expect("muat keyset");

    // Token ditandatangani kunci sah, tetapi header-nya mengaku kid lain.
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("kunci-palsu".into());
    let (encoding_key, _) = kunci_a.key_pair();
    let token = jsonwebtoken::encode(&header, &claims("core"), encoding_key).expect("encode");

    assert_eq!(
        jwt::verify_access(&config, &keyset, &token, "core").unwrap_err(),
        JwtError::UnknownKid
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[sqlx::test]
async fn rotate_menulis_file_dan_baris_baru_tanpa_mens_retire_kunci_lama(pool: PgPool) {
    let dir = dir_uji("rotate");

    let config = config_uji(&dir, "kunci-lama");
    let lama = SigningKey::load_or_generate(&config).expect("kunci lama");

    // Baris kunci lama harus tetap ada. Kunci lama sengaja tidak dipensiunkan
    // otomatis: token yang sudah terbit masih harus valid.
    db_keys::insert(&pool, &lama.kid, &lama.public_pem)
        .await
        .expect("daftarkan kunci lama");
    let baru = keys::rotate(&pool, &config)
        .await
        .expect("rotate butuh SANCA_KEY_DIR dan database");

    assert!(baru.kid.starts_with("kunci-lama-"), "kid: {}", baru.kid);
    assert_eq!(baru.kid.to_lowercase(), baru.kid, "kid harus huruf kecil");
    assert!(
        baru.kid
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
        "kid hanya [a-z0-9-]: {}",
        baru.kid
    );

    // File private baru harus ada, 0600, dan direktori 0700.
    let path = dir.join(format!("{}.pem", baru.kid));
    let isi = std::fs::read(&path).expect("file kunci baru harus ditulis");
    assert!(isi.starts_with(b"-----BEGIN"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "private key wajib 0600");
        let dir_mode = std::fs::metadata(&dir)
            .expect("metadata dir")
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700, "direktori kunci wajib 0700");
    }

    // Baris DB baru: aktif, belum pensiun.
    let (aktif, pensiun) = sqlx::query_as::<_, (bool, Option<time::OffsetDateTime>)>(
        "SELECT is_active, retired_at FROM signing_keys WHERE kid = $1",
    )
    .bind(&baru.kid)
    .fetch_one(&pool)
    .await
    .expect("baris kunci baru harus ada");
    assert!(aktif, "kunci baru harus is_active = true");
    assert!(pensiun.is_none(), "kunci baru belum pensiun");

    // Semua kunci hidup: kunci lama dan hasil rotate.
    let hidup = sqlx::query_as::<_, (String, Option<time::OffsetDateTime>)>(
        "SELECT kid, retired_at FROM signing_keys WHERE retired_at IS NULL",
    )
    .fetch_all(&pool)
    .await
    .expect("daftar kunci hidup");
    assert_eq!(
        hidup.len(),
        2,
        "tidak ada kunci yang di-retire otomatis: {hidup:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[sqlx::test]
async fn retire_kunci_lama_menghilangkan_kid_dari_jwks(pool: PgPool) {
    let dir = dir_uji("retire-lama");

    let config = config_uji(&dir, "kunci-lama");
    let lama = SigningKey::load_or_generate(&config).expect("kunci lama");
    db_keys::insert(&pool, &lama.kid, &lama.public_pem)
        .await
        .expect("daftarkan kunci lama");

    let baru = keys::rotate(&pool, &config).await.expect("rotate");

    // Sebelum retire: dua kid di JWKS, token kunci lama masih diterima.
    let baris = db_keys::list_active(&pool).await.expect("list_active");
    let pasangan: Vec<(String, String)> = baris
        .into_iter()
        .map(|row| (row.kid, row.public_pem))
        .collect();
    let sebelum = KeySet::load(&config, &pasangan, &[]).expect("keyset sebelum retire");
    assert_eq!(
        sebelum.kid(),
        baru.kid,
        "kunci hasil rotate jadi penanda tangan"
    );
    assert_eq!(kid_di_jwks(&sebelum).len(), 2);

    let hasil = keys::retire(&pool, &config, &lama.kid)
        .await
        .expect("retire kunci lama");
    assert_eq!(hasil.kid, lama.kid);
    assert_eq!(hasil.rows, 1, "satu baris signing_keys berubah");
    assert!(
        dir.join(format!("{}.pem", lama.kid)).exists(),
        "retire tidak boleh menghapus file private"
    );

    // Sesudah retire: baris ditandai pensiun, file hilang, JWKS tinggal satu.
    let (aktif, pensiun) = sqlx::query_as::<_, (bool, Option<time::OffsetDateTime>)>(
        "SELECT is_active, retired_at FROM signing_keys WHERE kid = $1",
    )
    .bind(&lama.kid)
    .fetch_one(&pool)
    .await
    .expect("baris kunci lama");
    assert!(!aktif, "kunci pensiun tidak aktif");
    assert!(pensiun.is_some(), "retired_at wajib terisi");
    assert!(
        dir.join(format!("{}.pem", lama.kid)).exists(),
        "file kunci pensiun tetap ada di disk"
    );

    let baris = db_keys::list_active(&pool).await.expect("list_active");
    let pasangan: Vec<(String, String)> = baris
        .into_iter()
        .map(|row| (row.kid, row.public_pem))
        .collect();
    let sesudah = KeySet::load(&config, &pasangan, &[]).expect("keyset sesudah retire");
    let kid = kid_di_jwks(&sesudah);
    assert_eq!(kid, vec![baru.kid.clone()], "hanya kunci baru yang tersisa");
    assert!(sesudah.verifier(&lama.kid).is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

#[sqlx::test]
async fn bootstrap_mendaftarkan_baris_dan_memuat_semua_kunci_hidup(pool: PgPool) {
    let dir = dir_uji("bootstrap");

    // Kondisi awal seperti di mesin dev: file kunci ada, tabel masih kosong.
    let config = config_uji(&dir, "kunci-lama");
    SigningKey::load_or_generate(&config).expect("kunci lama di disk");

    let keyset = keys::bootstrap(&pool, &config).await.expect("bootstrap");
    assert_eq!(keyset.kid(), "kunci-lama");
    assert_eq!(kid_di_jwks(&keyset), vec!["kunci-lama".to_string()]);
    assert_eq!(
        db_keys::list_active(&pool)
            .await
            .expect("list_active")
            .len(),
        1,
        "startup wajib mem-backfill baris untuk kunci yang filenya ada"
    );

    // Rotate lalu bootstrap lagi (setara restart server): kunci aktif berpindah
    // ke kid baru dan JWKS memuat semua kunci yang masih hidup.
    let baru = keys::rotate(&pool, &config).await.expect("rotate");
    let keyset = keys::bootstrap(&pool, &config)
        .await
        .expect("bootstrap setelah rotate");

    assert_eq!(
        keyset.kid(),
        baru.kid,
        "kunci hasil rotate jadi penanda tangan"
    );
    let kid = kid_di_jwks(&keyset);
    assert_eq!(kid.len(), 2, "JWKS memuat semua kunci hidup: {kid:?}");
    assert_eq!(kid[0], baru.kid);

    // Retire kunci lama: hilang dari JWKS/verifikasi, tetapi filenya tetap ada.
    keys::retire(&pool, &config, "kunci-lama")
        .await
        .expect("retire kunci lama");
    let keyset = keys::bootstrap(&pool, &config)
        .await
        .expect("bootstrap setelah retire");

    assert_eq!(kid_di_jwks(&keyset), vec![baru.kid.clone()]);
    assert!(keyset.verifier("kunci-lama").is_none());
    assert!(
        dir.join("kunci-lama.pem").exists(),
        "file kunci pensiun tidak boleh dihapus"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[sqlx::test]
async fn retire_kunci_aktif_ditolak(pool: PgPool) {
    let dir = dir_uji("retire-aktif");

    let config = config_uji(&dir, "kunci-lama");
    let lama = SigningKey::load_or_generate(&config).expect("kunci lama");
    db_keys::insert(&pool, &lama.kid, &lama.public_pem)
        .await
        .expect("daftarkan kunci lama");
    let baru = keys::rotate(&pool, &config).await.expect("rotate");

    // Kunci aktif tidak boleh dipensiunkan: server akan kehilangan penanda tangan.
    let err = keys::retire(&pool, &config, &baru.kid)
        .await
        .expect_err("retire kunci aktif harus ditolak");
    assert!(
        matches!(&err, KeyError::Active(kid) if kid == &baru.kid),
        "error harus menyebut kunci aktif, dapat: {err}"
    );

    // Kunci lama tetap ada dan masih aktif di database.
    let aktif = db_keys::list_active(&pool).await.expect("list_active");
    assert_eq!(aktif.len(), 2);
    assert!(dir.join(format!("{}.pem", lama.kid)).exists());

    let _ = std::fs::remove_dir_all(&dir);
}
