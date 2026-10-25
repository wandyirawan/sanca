//! Signing key RSA dan payload JWKS.
//!
//! Satu file PEM per `kid` di `SANCA_KEY_DIR` adalah mekanisme rotasi yang
//! dipilih (§14.7). Private key tidak pernah masuk database; yang disimpan di
//! tabel `signing_keys` hanya public key dalam bentuk PEM.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::{Engine, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use secrecy::ExposeSecret;
use serde_json::{Value, json};

use crate::config::Config;

/// Kegagalan memuat atau membuat signing key.
#[derive(Debug)]
pub enum KeyError {
    /// Tidak ada key di mana pun, dan proses tidak boleh generate sendiri.
    Missing,
    /// PEM tidak bisa dipakai sebagai kunci RSA.
    InvalidPem(String),
    /// Gagal membaca/menulis file key.
    Io(String),
    /// `openssl` tidak tersedia padahal dibutuhkan untuk generate key di dev.
    GeneratorUnavailable(String),
    /// Query tabel `signing_keys` gagal.
    Db(String),
    /// Kunci ini sedang dipakai menandatangani token, jadi tidak boleh pensiun.
    Active(String),
    /// Kunci ini sudah dipensiunkan sebelumnya.
    AlreadyRetired(String),
    /// Kid tidak dikenal, baik di database maupun di direktori kunci.
    Unknown(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Missing => write!(
                f,
                "tidak ada signing key: isi JWT_PRIVATE_KEY_PEM, JWT_PRIVATE_KEY_PATH, \
                 atau taruh <kid>.pem di SANCA_KEY_DIR (generate otomatis hanya di SANCA_ENV=dev)"
            ),
            KeyError::InvalidPem(msg) => write!(f, "PEM signing key tidak valid: {msg}"),
            KeyError::Io(msg) => write!(f, "gagal mengakses file signing key: {msg}"),
            KeyError::GeneratorUnavailable(msg) => write!(f, "gagal membuat signing key: {msg}"),
            KeyError::Db(msg) => write!(f, "gagal mengakses tabel signing_keys: {msg}"),
            KeyError::Active(kid) => write!(
                f,
                "tidak bisa mempensiunkan kunci aktif {kid}; rotate dulu, lalu pensiunkan \
                 kunci yang sudah tidak menandatangani token"
            ),
            KeyError::AlreadyRetired(kid) => write!(f, "kunci {kid} sudah dipensiunkan"),
            KeyError::Unknown(kid) => write!(f, "kunci {kid} tidak dikenal"),
        }
    }
}

impl std::error::Error for KeyError {}

/// Satu key aktif yang siap menandatangani dan memverifikasi token.
pub struct SigningKey {
    pub kid: String,
    /// Public key dalam PEM (SubjectPublicKeyInfo), siap disimpan di DB.
    pub public_pem: String,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    /// Modulus dan exponent base64url, dipakai apa adanya di JWKS.
    modulus: String,
    exponent: String,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Jangan pernah cetak material kunci, bahkan yang public.
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Muat key sesuai urutan prioritas, atau generate baru di development.
    ///
    /// Urutan: `JWT_PRIVATE_KEY_PEM` → `JWT_PRIVATE_KEY_PATH` →
    /// `SANCA_KEY_DIR/<kid>.pem` → generate (dev saja).
    pub fn load_or_generate(config: &Config) -> Result<Self, KeyError> {
        if let Some(pem) = &config.jwt_private_key_pem {
            return Self::from_pem(&config.jwt_kid, pem.expose_secret().as_bytes(), true);
        }

        if let Some(path) = &config.jwt_private_key_path {
            let pem =
                fs::read(path).map_err(|e| KeyError::Io(format!("{}: {e}", path.display())))?;
            return Self::from_pem(&config.jwt_kid, &pem, false);
        }

        if let Some(dir) = &config.sanca_key_dir {
            let path = key_path(dir, &config.jwt_kid);
            match fs::read(&path) {
                Ok(pem) => return Self::from_pem(&config.jwt_kid, &pem, false),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(KeyError::Io(format!("{}: {err}", path.display()))),
            }
        }

        if config.is_prod() {
            return Err(KeyError::Missing);
        }

        // Jalur bootstrap dev: generate RSA-3072, simpan ke SANCA_KEY_DIR kalau ada
        // supaya restart berikutnya memakai key yang sama (token lama tetap valid).
        let pem = generate_private_pem()?;
        if let Some(dir) = &config.sanca_key_dir {
            let path = key_path(dir, &config.jwt_kid);
            write_private_pem(dir, &path, &pem)?;
            eprintln!(
                "peringatan: signing key dev baru dibuat di {} (kid {}).",
                path.display(),
                config.jwt_kid
            );
        } else {
            eprintln!(
                "peringatan: signing key dev dibuat di memori dan hilang saat proses berhenti; \
                 set SANCA_KEY_DIR untuk menyimpannya."
            );
        }

        Self::from_pem(&config.jwt_kid, &pem, false)
    }

    /// Bangun key dari PEM private (PKCS#8 atau PKCS#1).
    ///
    /// `encoded` menandai PEM yang datang dari env sebagai base64 (§7 menulis
    /// "base64 PEM"), jadi isi non-PEM dicoba di-decode dulu.
    fn from_pem(kid: &str, pem: &[u8], encoded: bool) -> Result<Self, KeyError> {
        let pem = if encoded {
            decode_env_pem(pem)?
        } else {
            pem.to_vec()
        };

        let encoding_key =
            EncodingKey::from_rsa_pem(&pem).map_err(|e| KeyError::InvalidPem(e.to_string()))?;

        let jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256)
            .map_err(|e| KeyError::InvalidPem(e.to_string()))?;

        let AlgorithmParameters::RSA(rsa) = jwk.algorithm else {
            return Err(KeyError::InvalidPem("bukan kunci RSA".into()));
        };

        // Verifikasi memakai komponen (n, e) dari private key, bukan file public
        // terpisah, supaya tidak ada dua sumber kebenaran yang bisa berbeda.
        let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
            .map_err(|e| KeyError::InvalidPem(e.to_string()))?;

        let public_pem = public_pem_from_components(&rsa.n, &rsa.e)?;

        Ok(SigningKey {
            kid: kid.to_string(),
            public_pem,
            encoding_key,
            decoding_key,
            modulus: rsa.n,
            exponent: rsa.e,
        })
    }

    /// Pasangan kunci untuk `jsonwebtoken`.
    pub fn key_pair(&self) -> (&EncodingKey, &DecodingKey) {
        (&self.encoding_key, &self.decoding_key)
    }

    /// Satu JWK RS256 untuk key ini (`kty`, `use`, `alg`, `kid`, `n`, `e`).
    pub fn jwk(&self) -> Value {
        json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "n": self.modulus,
            "e": self.exponent,
        })
    }

    /// Payload `/.well-known/jwks.json`. Versi satu kunci ini dipakai jalur
    /// yang memang hanya punya satu key; `KeySet` mempublikasikan semuanya.
    pub fn jwks_json(&self) -> Value {
        json!({ "keys": [self.jwk()] })
    }
}

/// Kumpulan kunci yang masih hidup.
///
/// Satu kunci aktif menandatangani token baru; semua kunci lain yang belum
/// dipensiunkan tetap bisa memverifikasi token lama dan tetap dipublikasikan di
/// JWKS. Inilah yang membuat rotasi kunci tidak memutus sesi yang sedang jalan.
pub struct KeySet {
    active: SigningKey,
    /// Decoding key per `kid`, termasuk kunci aktif.
    verifiers: HashMap<String, DecodingKey>,
    /// JWKS semua kunci hidup, kunci aktif di urutan pertama.
    jwks: Vec<Value>,
}

impl fmt::Debug for KeySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySet")
            .field("active", &self.active)
            .field("kunci", &self.verifiers.len())
            .finish()
    }
}

impl KeySet {
    /// Keyset minimal dari satu kunci; dipakai test dan jalur yang memang
    /// hanya punya satu key (misalnya `JWT_PRIVATE_KEY_PEM`).
    pub fn from_signing_key(active: SigningKey) -> Self {
        let mut verifiers = HashMap::new();
        verifiers.insert(active.kid.clone(), active.decoding_key.clone());
        let jwks = vec![active.jwk()];

        Self {
            active,
            verifiers,
            jwks,
        }
    }

    /// Muat semua kunci hidup.
    ///
    /// `live` adalah pasangan `(kid, public_pem)` dari tabel `signing_keys` yang
    /// `retired_at IS NULL`, terbaru dulu. `retired` berisi `kid` yang sudah
    /// dipensiunkan: filenya boleh saja masih ada di disk (retire sengaja tidak
    /// menghapus file), tetapi kunci itu tidak boleh ikut JWKS maupun dipakai
    /// memverifikasi token.
    ///
    /// Material private diambil dari file `<kid>.pem` kalau ada; kalau tidak,
    /// kunci tetap bisa memverifikasi lewat `public_pem` di database. Bila
    /// `live` kosong (database belum diisi, misalnya di unit test), semua file
    /// di SANCA_KEY_DIR dianggap hidup kecuali yang ada di `retired`.
    pub fn load(
        config: &Config,
        live: &[(String, String)],
        retired: &[String],
    ) -> Result<Self, KeyError> {
        let pensiun: HashSet<&str> = retired.iter().map(String::as_str).collect();
        let dari_dir = private_keys_in_dir(config)?;

        // Kunci aktif = baris hidup terbaru yang file private-nya ada, supaya
        // hasil `sanca key rotate` langsung terpakai setelah server restart.
        let kid_aktif = active_kid(config, live);

        // `load_or_generate` memakai `jwt_kid` sebagai nama file, jadi kunci
        // aktif cukup ditunjuk lewat salinan config.
        let mut config_aktif = config.clone();
        config_aktif.jwt_kid = kid_aktif;
        let active = SigningKey::load_or_generate(&config_aktif)?;

        let mut keyset = Self::from_signing_key(active);

        // (a) Kunci hidup menurut database adalah daftar resminya.
        for (kid, public_pem) in live {
            if pensiun.contains(kid.as_str()) || keyset.verifiers.contains_key(kid) {
                continue;
            }

            match dari_dir.iter().find(|(k, _)| k == kid) {
                Some((_, key)) => {
                    let jwk = key.jwk();
                    keyset.insert(kid.clone(), key.decoding_key.clone(), jwk);
                }
                None => {
                    let (decoding_key, jwk) = verifier_from_public_pem(kid, public_pem)?;
                    keyset.insert(kid.clone(), decoding_key, jwk);
                }
            }
        }

        // (b) Jaring pengaman untuk jalur tanpa database (test, bootstrap awal):
        // setiap file yang bukan milik kunci pensiun dianggap hidup.
        if live.is_empty() {
            for (kid, key) in dari_dir {
                if pensiun.contains(kid.as_str()) || keyset.verifiers.contains_key(&kid) {
                    continue;
                }
                let jwk = key.jwk();
                keyset.insert(kid, key.decoding_key, jwk);
            }
        }

        Ok(keyset)
    }

    /// Kunci yang dipakai menandatangani token baru.
    pub fn signing_key(&self) -> &SigningKey {
        &self.active
    }

    /// `kid` kunci aktif.
    pub fn kid(&self) -> &str {
        &self.active.kid
    }

    /// Decoding key untuk `kid`, atau `None` kalau kunci itu sudah tidak hidup.
    pub fn verifier(&self, kid: &str) -> Option<&DecodingKey> {
        self.verifiers.get(kid)
    }

    /// Payload `/.well-known/jwks.json` dari semua kunci hidup.
    pub fn jwks_json(&self) -> Value {
        json!({ "keys": self.jwks })
    }

    fn insert(&mut self, kid: String, decoding_key: DecodingKey, jwk: Value) {
        self.verifiers.insert(kid, decoding_key);
        self.jwks.push(jwk);
    }
}

impl From<SigningKey> for KeySet {
    fn from(key: SigningKey) -> Self {
        Self::from_signing_key(key)
    }
}

/// Hasil `sanca key retire`, untuk dicetak CLI.
#[derive(Debug)]
pub struct RetiredKey {
    pub kid: String,
    /// Jumlah baris `signing_keys` yang berubah.
    pub rows: u64,
}

/// Siapkan keyset saat startup.
///
/// Tabel `signing_keys` adalah satu-satunya sumber kebenaran status kunci:
/// file `*.pem` hanya menyediakan material private. Karena itu setiap kunci
/// yang punya material private tetapi belum punya baris DB didaftarkan lebih
/// dulu (`ON CONFLICT DO NOTHING`), sehingga `sanca key retire` tidak pernah
/// menjawab "kunci tidak dikenal" untuk kunci yang benar-benar ada.
pub async fn bootstrap(pool: &sqlx::PgPool, config: &Config) -> Result<KeySet, KeyError> {
    for (kid, key) in private_keys_in_dir(config)? {
        crate::db::keys::backfill(pool, &kid, &key.public_pem)
            .await
            .map_err(db_error)?;
    }

    let live = crate::db::keys::list_active(pool).await.map_err(db_error)?;
    let live: Vec<(String, String)> = live
        .into_iter()
        .map(|row| (row.kid, row.public_pem))
        .collect();
    let pensiun = crate::db::keys::list_retired(pool)
        .await
        .map_err(db_error)?;

    let keyset = KeySet::load(config, &live, &pensiun)?;

    // Kunci aktif bisa lahir dari generate dev atau dari env, jadi barisnya
    // didaftarkan setelah keyset terbentuk.
    crate::db::keys::backfill(pool, keyset.kid(), &keyset.signing_key().public_pem)
        .await
        .map_err(db_error)?;
    crate::db::keys::mark_active(pool, keyset.kid())
        .await
        .map_err(db_error)?;

    Ok(keyset)
}

/// Buat kunci signing baru, simpan file private-nya, dan daftarkan public key
/// ke tabel `signing_keys`.
///
/// Kunci lama sengaja tidak dipensiunkan di sini: token yang sudah terbit harus
/// tetap valid sampai operator memanggil `retire`.
pub async fn rotate(pool: &sqlx::PgPool, config: &Config) -> Result<SigningKey, KeyError> {
    let Some(dir) = &config.sanca_key_dir else {
        return Err(KeyError::Io(
            "SANCA_KEY_DIR wajib diisi supaya kunci baru punya tempat tinggal".into(),
        ));
    };

    let kid = kid_baru(&config.jwt_kid);
    let path = key_path(dir, &kid);
    if path.exists() {
        return Err(KeyError::Io(format!(
            "kunci {kid} sudah ada; tunggu satu detik lalu jalankan lagi"
        )));
    }

    let pem = generate_private_pem()?;
    write_private_pem(dir, &path, &pem)?;
    let key = SigningKey::from_pem(&kid, &pem, false)?;

    if let Err(err) = crate::db::keys::insert(pool, &kid, &key.public_pem).await {
        // Jangan tinggalkan file tanpa baris DB: itu kunci hantu yang tetap
        // masuk JWKS tapi tidak bisa dilacak asalnya.
        let _ = fs::remove_file(&path);
        return Err(KeyError::Db(err.to_string()));
    }

    Ok(key)
}

/// Pensiunkan satu kunci.
///
/// Status pensiun hanya dicatat di database (`is_active = false`,
/// `retired_at = now()`). File private-nya sengaja TIDAK dihapus: penghapusan
/// file adalah tugas operator, dan menghapusnya otomatis pernah membuat kunci
/// yang masih dipakai memverifikasi token hilang dari disk.
///
/// Kunci yang sedang aktif (yang menandatangani token baru) ditolak, karena
/// server akan kehilangan penanda tangan sampai ada kunci pengganti.
pub async fn retire(
    pool: &sqlx::PgPool,
    config: &Config,
    kid: &str,
) -> Result<RetiredKey, KeyError> {
    let live = crate::db::keys::list_active(pool).await.map_err(db_error)?;
    let live: Vec<(String, String)> = live
        .into_iter()
        .map(|row| (row.kid, row.public_pem))
        .collect();

    // Aturan kunci aktif harus sama persis dengan yang dipakai `KeySet::load`,
    // supaya CLI dan server tidak pernah berbeda pendapat.
    if active_kid(config, &live) == kid {
        return Err(KeyError::Active(kid.to_string()));
    }

    if !live.iter().any(|(row_kid, _)| row_kid == kid) {
        return if crate::db::keys::exists(pool, kid).await.map_err(db_error)? {
            Err(KeyError::AlreadyRetired(kid.to_string()))
        } else {
            Err(KeyError::Unknown(kid.to_string()))
        };
    }

    let rows = crate::db::keys::retire(pool, kid).await.map_err(db_error)?;

    if rows == 0 {
        return Err(KeyError::Unknown(kid.to_string()));
    }

    Ok(RetiredKey {
        kid: kid.to_string(),
        rows,
    })
}

/// `kid` kunci aktif: baris hidup terbaru yang file private-nya ada.
///
/// Urutan baris (terbaru dulu) datang dari `signing_keys.created_at`, jadi
/// kunci hasil `rotate` otomatis menjadi penanda tangan setelah restart.
/// Kalau tidak ada baris yang cocok, jatuh ke `JWT_KID`; pemanggil yang
/// memutuskan generate kunci baru (hanya di dev).
fn active_kid(config: &Config, live: &[(String, String)]) -> String {
    if config.jwt_private_key_pem.is_some() || config.jwt_private_key_path.is_some() {
        return config.jwt_kid.clone();
    }

    if let Some(dir) = &config.sanca_key_dir
        && let Some((kid, _)) = live.iter().find(|(kid, _)| key_path(dir, kid).is_file())
    {
        return kid.clone();
    }

    config.jwt_kid.clone()
}

/// Terjemahkan kegagalan query `signing_keys` menjadi `KeyError`.
fn db_error(err: sqlx::Error) -> KeyError {
    KeyError::Db(err.to_string())
}

/// Semua private key di direktori kunci, diurutkan menurut nama file supaya
/// urutan JWKS stabil antar restart. Kunci dari env tidak punya file, jadi
/// tidak ikut di sini.
fn private_keys_in_dir(config: &Config) -> Result<Vec<(String, SigningKey)>, KeyError> {
    let Some(dir) = &config.sanca_key_dir else {
        return Ok(Vec::new());
    };
    let dir = dir.as_path();

    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(KeyError::Io(format!("{}: {err}", dir.display()))),
    };

    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| KeyError::Io(format!("{}: {e}", dir.display())))?
            .path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("pem") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut keys = Vec::with_capacity(paths.len());
    for path in paths {
        let Some(kid) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        let pem = fs::read(&path).map_err(|e| KeyError::Io(format!("{}: {e}", path.display())))?;
        keys.push((kid.to_string(), SigningKey::from_pem(kid, &pem, false)?));
    }

    Ok(keys)
}

/// Decoding key dan JWK dari public key PEM (kolom `signing_keys.public_pem`).
fn verifier_from_public_pem(kid: &str, public_pem: &str) -> Result<(DecodingKey, Value), KeyError> {
    let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
        .map_err(|e| KeyError::InvalidPem(format!("{kid}: {e}")))?;

    let jwk = Jwk::from_decoding_key(&decoding_key, Some(Algorithm::RS256))
        .map_err(|e| KeyError::InvalidPem(format!("{kid}: {e}")))?;
    let AlgorithmParameters::RSA(rsa) = jwk.algorithm else {
        return Err(KeyError::InvalidPem(format!("{kid}: bukan kunci RSA")));
    };

    Ok((
        decoding_key,
        json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": rsa.n,
            "e": rsa.e,
        }),
    ))
}

/// `kid` kunci baru: `<JWT_KID>-<YYYYMMDD-HHMMSS>`, huruf kecil, hanya
/// `[a-z0-9-]`.
fn kid_baru(base: &str) -> String {
    let now = time::OffsetDateTime::now_utc();
    let base: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let base = base.trim_matches('-');
    let base = if base.is_empty() { "sanca" } else { base };

    format!(
        "{base}-{:04}{:02}{:02}-{:02}{:02}{:02}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// Path file private key untuk satu `kid`.
fn key_path(dir: &Path, kid: &str) -> PathBuf {
    dir.join(format!("{kid}.pem"))
}

/// Tulis private key dengan izin 0600 dan direktori 0700.
fn write_private_pem(dir: &Path, path: &Path, pem: &[u8]) -> Result<(), KeyError> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    fs::create_dir_all(dir).map_err(|e| KeyError::Io(format!("{}: {e}", dir.display())))?;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| KeyError::Io(format!("{}: {e}", path.display())))?;
    file.write_all(pem)
        .map_err(|e| KeyError::Io(format!("{}: {e}", path.display())))
}

/// Generate private key RSA-3072 lewat `openssl`.
///
/// Tidak ada crate keygen di daftar dependency, dan ini hanya jalan bootstrap
/// development; produksi selalu memakai key yang sudah ada.
fn generate_private_pem() -> Result<Vec<u8>, KeyError> {
    let output = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:3072",
        ])
        .output()
        .map_err(|e| {
            KeyError::GeneratorUnavailable(format!("openssl tidak bisa dijalankan: {e}"))
        })?;

    if !output.status.success() {
        return Err(KeyError::GeneratorUnavailable(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    Ok(output.stdout)
}

/// PEM dari env boleh berupa PEM biasa atau base64 dari PEM.
fn decode_env_pem(raw: &[u8]) -> Result<Vec<u8>, KeyError> {
    if raw.starts_with(b"-----BEGIN") {
        return Ok(raw.to_vec());
    }

    let compact: String = String::from_utf8_lossy(raw)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    STANDARD
        .decode(compact.as_bytes())
        .map_err(|_| KeyError::InvalidPem("JWT_PRIVATE_KEY_PEM bukan PEM maupun base64".into()))
}

/// Susun PEM SubjectPublicKeyInfo dari komponen RSA (n, e) base64url.
///
/// `jsonwebtoken` tidak mengekspos public key sebagai PEM, jadi DER-nya dirakit
/// di sini: bisa diverifikasi dengan `openssl pkey -pubin -text -noout`.
fn public_pem_from_components(n_b64: &str, e_b64: &str) -> Result<String, KeyError> {
    let n = URL_SAFE_NO_PAD
        .decode(n_b64)
        .map_err(|_| KeyError::InvalidPem("modulus bukan base64url".into()))?;
    let e = URL_SAFE_NO_PAD
        .decode(e_b64)
        .map_err(|_| KeyError::InvalidPem("exponent bukan base64url".into()))?;

    // AlgorithmIdentifier: rsaEncryption (1.2.840.113549.1.1.1) + NULL.
    let oid = tlv(
        0x06,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
    );
    let algorithm = tlv(0x30, &[oid, tlv(0x05, &[])].concat());

    let mut rsa_public = integer(&n);
    rsa_public.extend(integer(&e));

    // BIT STRING diawali jumlah bit tak terpakai (0).
    let mut bit_string = vec![0u8];
    bit_string.extend(tlv(0x30, &rsa_public));
    let bit_string = tlv(0x03, &bit_string);

    let der = tlv(0x30, &[algorithm, bit_string].concat());
    Ok(to_pem("PUBLIC KEY", &der))
}

/// Satu elemen DER: tag, panjang, isi.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    out.extend(der_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// Panjang DER dalam bentuk pendek atau panjang (0x81/0x82/...).
fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }

    let bytes: Vec<u8> = len
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

/// DER INTEGER: buang nol di depan, tambah nol kalau bit tanda ikut menyala.
fn integer(bytes: &[u8]) -> Vec<u8> {
    let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
    let mut value = if trimmed.is_empty() { vec![0] } else { trimmed };

    if value[0] & 0x80 != 0 {
        value.insert(0, 0);
    }

    tlv(0x02, &value)
}

/// Bungkus DER menjadi PEM dengan lebar baris 64 karakter.
fn to_pem(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));
    pem
}
