//! Aturan alur `authorization_code` + PKCE.
//!
//! Semua keputusan yang menentukan keamanan alur ini ada di sini, bukan di
//! handler: app mana yang boleh, `redirect_uri` mana yang sah, kapan PKCE wajib,
//! dan bagaimana kode dibuat. Handler `api::oauth_authorize` hanya mengurus
//! bentuk request dan respons, jadi aturan yang sama dipakai halaman consent
//! GET maupun POST tanpa dua salinan yang bisa menyimpang.
//!
//! Batas kepercayaan yang dipakai:
//! - `kind = spa` wajib PKCE (`S256`); `web` boleh tanpa PKCE tetapi tetap
//!   didukung kalau mengirim. `service`/`cli` tidak punya manusia yang bisa
//!   menyetujui, jadi ditolak untuk alur ini.
//! - `redirect_uri` harus sama persis dengan salah satu entri `apps.redirect_uris`.
//!   Prefix, wildcard, atau normalisasi tidak dipakai: satu karakter beda = tolak.
//! - Kode mentah hanya keluar sekali ke client. Yang disimpan SHA-256 hex.

use rand::TryRngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::apps::{App, AppKind};
use crate::db::oauth_codes;
use crate::db::sessions;
use crate::error::AppError;

/// Umur authorization code. Pendek disengaja: kode hanya perlu bertahan selama
/// redirect browser ke client, bukan selama sesi.
pub const CODE_TTL_SECS: i64 = 60;

/// Panjang kode mentah sebelum base64url.
const CODE_BYTES: usize = 32;

/// Satu-satunya metode PKCE yang diterima. `plain` ditolak karena tidak
/// melindungi apa pun kalau code challenge ikut bocor di URL.
pub const PKCE_METHOD_S256: &str = "S256";

/// Panjang `code_challenge` menurut RFC 7636: base64url dari SHA-256 = 43 karakter.
const CHALLENGE_MIN: usize = 43;
const CHALLENGE_MAX: usize = 128;

/// Panjang `code_verifier` menurut RFC 7636 §4.1.
const VERIFIER_MIN: usize = 43;
const VERIFIER_MAX: usize = 128;

/// Batas panjang `user_agent` yang disimpan di baris sesi; header bisa panjang
/// sewenang-wenang dan tidak ada gunanya menyimpan seluruhnya.
const MAX_USER_AGENT: usize = 512;

/// Panjang refresh token mentah sebelum base64url.
const REFRESH_BYTES: usize = 32;

/// Parameter otorisasi yang sudah dinormalkan dari query atau form.
#[derive(Debug, Clone, Default)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    /// Scope yang diminta, sudah dipecah dari string berspasi.
    pub scope: Vec<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// Penolakan pada tahap validasi. `code` mengikuti nama error OAuth supaya
/// pesannya bisa dipakai apa adanya di halaman error.
#[derive(Debug, Clone)]
pub struct AuthorizeError {
    pub code: &'static str,
    pub description: String,
}

impl AuthorizeError {
    fn invalid_request(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_request",
            description: description.into(),
        }
    }

    fn invalid_scope(description: impl Into<String>) -> Self {
        Self {
            code: "invalid_scope",
            description: description.into(),
        }
    }
}

/// Pecah parameter `scope` (dipisah spasi) menjadi daftar unik terurut.
pub fn parse_scope(raw: &str) -> Vec<String> {
    let mut scopes: Vec<String> = raw
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    scopes.sort();
    scopes.dedup();
    scopes
}

/// Validasi permintaan otorisasi terhadap satu app.
///
/// Urutannya penting: `response_type`, jenis app, lalu `redirect_uri`, baru PKCE.
/// `redirect_uri` diperiksa sebelum apa pun yang bisa memantulkan pesan ke URI
/// itu, supaya permintaan dengan URI tak terdaftar tidak pernah jadi redirect.
pub fn validate_authorize(app: &App, request: &AuthorizeRequest) -> Result<(), AuthorizeError> {
    if !app.is_active {
        return Err(AuthorizeError::invalid_request(
            "aplikasi ini sedang tidak aktif",
        ));
    }

    if request.response_type != "code" {
        return Err(AuthorizeError::invalid_request(
            "response_type harus `code` untuk alur ini",
        ));
    }

    match app.kind {
        AppKind::Web | AppKind::Spa => {}
        AppKind::Service | AppKind::Cli => {
            return Err(AuthorizeError::invalid_request(
                "alur authorization code hanya untuk aplikasi web atau spa",
            ));
        }
    }

    // Exact match, bukan prefix: `http://localhost:9000/cb` tidak boleh cocok
    // dengan `http://localhost:9000/cb/anything` maupun `http://evil.test`.
    if !app
        .redirect_uris
        .iter()
        .any(|uri| uri == &request.redirect_uri)
    {
        return Err(AuthorizeError::invalid_request(
            "redirect_uri tidak terdaftar untuk aplikasi ini",
        ));
    }

    validate_pkce(app.kind, request)
}

/// Aturan PKCE: wajib untuk `spa`, opsional untuk `web`, dan hanya `S256`.
fn validate_pkce(kind: AppKind, request: &AuthorizeRequest) -> Result<(), AuthorizeError> {
    match request.code_challenge.as_deref() {
        None => {
            if kind == AppKind::Spa {
                return Err(AuthorizeError::invalid_request(
                    "aplikasi spa wajib mengirim code_challenge (PKCE)",
                ));
            }
            if request.code_challenge_method.is_some() {
                return Err(AuthorizeError::invalid_request(
                    "code_challenge_method dikirim tanpa code_challenge",
                ));
            }
            Ok(())
        }
        Some(challenge) => {
            // Tanpa method, RFC 7636 menganggap `plain`; itu justru yang ditolak.
            let method = request.code_challenge_method.as_deref().unwrap_or("plain");
            if method != PKCE_METHOD_S256 {
                return Err(AuthorizeError::invalid_request(
                    "code_challenge_method hanya mendukung S256",
                ));
            }
            if !is_valid_challenge(challenge) {
                return Err(AuthorizeError::invalid_request(
                    "bentuk code_challenge tidak sah",
                ));
            }
            Ok(())
        }
    }
}

/// `code_challenge` harus base64url tanpa padding, panjang 43–128 karakter.
fn is_valid_challenge(challenge: &str) -> bool {
    let panjang_ok = (CHALLENGE_MIN..=CHALLENGE_MAX).contains(&challenge.len());
    let karakter_ok = challenge
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    panjang_ok && karakter_ok
}

/// Scope yang benar-benar diberikan: irisan permintaan dengan permission user
/// di app tujuan. Permintaan kosong berarti seluruh permission user.
///
/// Scope yang tidak dimiliki user ditolak, bukan dibuang diam-diam: client yang
/// meminta lebih harus tahu tokennya tidak akan memuat izin itu.
pub fn granted_scopes(
    available: &[String],
    requested: &[String],
) -> Result<Vec<String>, AuthorizeError> {
    if requested.is_empty() {
        return Ok(available.to_vec());
    }

    let mut granted: Vec<String> = Vec::with_capacity(requested.len());
    for scope in requested {
        if !available.iter().any(|item| item == scope) {
            return Err(AuthorizeError::invalid_scope(format!(
                "scope `{scope}` tidak dimiliki pengguna di aplikasi ini"
            )));
        }
        if !granted.iter().any(|item| item == scope) {
            granted.push(scope.clone());
        }
    }
    Ok(granted)
}

/// Ikatan satu kode ke pemiliknya: app, user, sesi, tujuan, dan PKCE-nya.
pub struct CodeGrant<'a> {
    pub app_id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub redirect_uri: &'a str,
    pub scope: &'a [String],
    pub code_challenge: Option<&'a str>,
    pub challenge_method: Option<&'a str>,
}

/// Buat kode baru, simpan hash-nya, lalu kembalikan nilai mentah untuk redirect.
///
/// Nilai mentah hanya hidup di nilai kembalian ini; setelah handler menempelkannya
/// ke URL, tidak ada lagi salinan di database maupun di log.
pub async fn issue_code(pool: &PgPool, grant: &CodeGrant<'_>) -> Result<String, AppError> {
    let code = random_code();
    let hash = hash_code(&code);
    let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(CODE_TTL_SECS);

    let new_code = oauth_codes::NewCode {
        code_hash: &hash,
        app_id: grant.app_id,
        user_id: grant.user_id,
        session_id: grant.session_id,
        redirect_uri: grant.redirect_uri,
        scope: grant.scope,
        code_challenge: grant.code_challenge,
        challenge_method: grant.challenge_method,
        expires_at,
    };

    oauth_codes::insert(pool, &new_code).await.map_err(|err| {
        tracing::error!(error = %err, "gagal menyimpan authorization code");
        AppError::Internal
    })?;

    Ok(code)
}

/// SHA-256 hex dari kode. Satu arah: tidak ada jalur untuk memulihkan kode asli.
pub fn hash_code(code: &str) -> String {
    let digest = Sha256::digest(code.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// 32 byte acak dari RNG sistem, base64url tanpa padding.
fn random_code() -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let mut bytes = [0u8; CODE_BYTES];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("RNG sistem harus selalu tersedia");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Tempelkan parameter ke `redirect_uri` yang sudah divalidasi, dengan `&` kalau
/// URI itu sudah punya query sendiri.
pub fn append_query(base: &str, params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return base.to_string();
    }

    let separator = if base.contains('?') { '&' } else { '?' };
    let mut url = String::with_capacity(base.len() + 64);
    url.push_str(base);
    url.push(separator);
    for (index, (key, value)) in params.iter().enumerate() {
        if index > 0 {
            url.push('&');
        }
        url.push_str(&encode_component(key));
        url.push('=');
        url.push_str(&encode_component(value));
    }
    url
}

/// Percent-encode untuk satu komponen query. Hanya karakter unreserved
/// (RFC 3986) yang dibiarkan; sisanya di-encode per byte UTF-8.
pub fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Kebalikan `encode_component`, untuk nilai `application/x-www-form-urlencoded`.
///
/// Hanya dipakai membaca parameter token (`code`, `code_verifier`,
/// `redirect_uri`, `refresh_token`), yang memang bisa memuat `%` dan `+` setelah
/// di-encode klien. Escape yang rusak dibiarkan apa adanya, bukan error: nilainya
/// tetap akan gagal pada pemeriksaan berikutnya.
pub fn decode_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
                match hex.and_then(|hex| u8::from_str_radix(hex, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    None => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            // Form HTML mengirim spasi sebagai `+`.
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            other => {
                out.push(other);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// Kegagalan pada tahap tukar kode/rotasi refresh.
///
/// Handler memetakan `InvalidGrant` ke 400 dan `Internal` ke 500; pembedaan ini
/// yang membuat pesan internal tidak pernah sampai ke klien.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantError {
    /// Kode/refresh tidak dikenal, sudah dipakai, kedaluwarsa, atau bukan milik
    /// client ini. Semua sebab itu dijawab sama supaya tidak bisa dibedakan.
    InvalidGrant,
    /// Kesalahan di sisi kita; detailnya hanya masuk log.
    Internal,
}

/// Hasil penukaran authorization code.
pub struct ExchangedCode {
    pub user_id: Uuid,
    /// Sesi console yang tercatat di baris kode; menjadi klaim `sid`.
    pub sid: Uuid,
    /// Scope yang disetujui saat consent, apa adanya dari baris kode.
    pub scope: Vec<String>,
    /// Refresh token mentah; hanya hidup di nilai kembalian ini.
    pub refresh_token: String,
}

/// Hasil rotasi refresh token.
pub struct RefreshedSession {
    pub user_id: Uuid,
    /// Sesi baru hasil rotasi; menjadi klaim `sid`.
    pub sid: Uuid,
    pub refresh_token: String,
}

/// Verifikasi PKCE `S256`.
///
/// Kode tanpa `code_challenge` (app `web` yang tidak memakai PKCE) selalu lolos:
/// verifier diabaikan. Kode dengan challenge mewajibkan verifier yang S256-nya
/// sama persis. Perbandingan memakai `==` biasa karena challenge-nya sendiri
/// publik (ikut di URL redirect), jadi tidak ada rahasia yang bisa ditebak dari
/// selisih waktu.
pub fn verify_pkce(challenge: Option<&str>, verifier: Option<&str>) -> bool {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let Some(challenge) = challenge else {
        return true;
    };
    let Some(verifier) = verifier else {
        return false;
    };
    if !(VERIFIER_MIN..=VERIFIER_MAX).contains(&verifier.len()) {
        return false;
    }

    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == challenge
}

/// Tukar authorization code menjadi sesi + refresh token.
///
/// Urutannya adalah keamanannya:
/// 1. kode dikonsumsi atomik lebih dulu, jadi percobaan kedua — termasuk yang
///    datang bersamaan — tidak mendapat baris apa pun;
/// 2. app pemilik kode harus app yang sedang menukar;
/// 3. `redirect_uri` harus sama persis dengan yang terikat di baris kode;
/// 4. PKCE diperiksa terakhir, sebelum sesi dibuat.
///
/// Kode yang gagal di langkah mana pun tetap hangus: lebih baik klien mengulang
/// alur otorisasi daripada kode yang sudah salah tetap bisa dipakai.
pub async fn exchange_code(
    pool: &PgPool,
    app: &App,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
    user_agent: &str,
    ip: Option<&str>,
) -> Result<ExchangedCode, GrantError> {
    let stored = oauth_codes::consume(pool, &hash_code(code))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "gagal mengonsumsi authorization code");
            GrantError::Internal
        })?
        .ok_or(GrantError::InvalidGrant)?;

    if stored.app_id != app.id {
        return Err(GrantError::InvalidGrant);
    }

    if stored.redirect_uri != redirect_uri {
        return Err(GrantError::InvalidGrant);
    }

    if !verify_pkce(stored.code_challenge.as_deref(), code_verifier) {
        return Err(GrantError::InvalidGrant);
    }

    let (_, refresh_token) = start_session(pool, app, stored.user_id, user_agent, ip).await?;

    Ok(ExchangedCode {
        user_id: stored.user_id,
        sid: stored.session_id,
        scope: stored.scope,
        refresh_token,
    })
}

/// Rotasi refresh token: sesi lama dicabut, sesi baru diterbitkan.
///
/// Pencabutan dilakukan lebih dulu dan wajib berhasil. Kalau dua request memakai
/// refresh token yang sama, hanya satu yang mendapat `true`; yang kalah ditolak,
/// sehingga satu refresh token tidak pernah menjadi dua sesi hidup.
pub async fn rotate_refresh(
    pool: &PgPool,
    app: &App,
    refresh_token: &str,
    user_agent: &str,
    ip: Option<&str>,
) -> Result<RefreshedSession, GrantError> {
    let found = sessions::by_refresh_hash(pool, &hash_code(refresh_token))
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "gagal mencari sesi dari refresh token");
            GrantError::Internal
        })?;

    let Some(session) = found else {
        return Err(GrantError::InvalidGrant);
    };

    if session.app_id != app.id {
        return Err(GrantError::InvalidGrant);
    }

    let revoked = sessions::revoke(pool, session.id).await.map_err(|err| {
        tracing::error!(error = %err, "gagal mencabut sesi lama saat rotasi");
        GrantError::Internal
    })?;
    if !revoked {
        return Err(GrantError::InvalidGrant);
    }

    let (sid, refresh_token) = start_session(pool, app, session.user_id, user_agent, ip).await?;

    Ok(RefreshedSession {
        user_id: session.user_id,
        sid,
        refresh_token,
    })
}

/// Buat baris sesi baru untuk satu user di satu app.
///
/// Yang disimpan hanya hash refresh token; nilai mentahnya dikembalikan sekali
/// ke pemanggil untuk dikirim ke klien.
async fn start_session(
    pool: &PgPool,
    app: &App,
    user_id: Uuid,
    user_agent: &str,
    ip: Option<&str>,
) -> Result<(Uuid, String), GrantError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let mut bytes = [0u8; REFRESH_BYTES];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("RNG sistem harus selalu tersedia");
    let refresh_token = URL_SAFE_NO_PAD.encode(bytes);

    let expires_at =
        OffsetDateTime::now_utc() + time::Duration::seconds(app.refresh_ttl_secs as i64);
    let user_agent: String = user_agent.chars().take(MAX_USER_AGENT).collect();

    let session_id = sessions::insert(
        pool,
        user_id,
        app.id,
        &hash_code(&refresh_token),
        expires_at,
        &user_agent,
        ip,
    )
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "gagal menyimpan sesi untuk token");
        GrantError::Internal
    })?;

    Ok((session_id, refresh_token))
}
