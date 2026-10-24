//! Signing key RSA dan payload JWKS.
//!
//! Satu file PEM per `kid` di `SANCA_KEY_DIR` adalah mekanisme rotasi yang
//! dipilih (§14.7). Private key tidak pernah masuk database; yang disimpan di
//! tabel `signing_keys` hanya public key dalam bentuk PEM.

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

    /// Payload `/.well-known/jwks.json`. Untuk sekarang hanya key aktif ini;
    /// key yang sudah dipensiunkan tidak ikut dipublikasikan.
    pub fn jwks_json(&self) -> Value {
        json!({ "keys": [self.jwk()] })
    }
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
