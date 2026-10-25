//! Access token RS256: klaim persis §6 AGENTS, verifikasi aud + iss + exp.

use std::fmt;

use jsonwebtoken::{
    Algorithm, Header, Validation, decode, decode_header, encode, errors::ErrorKind,
};
use serde::{Deserialize, Serialize};

use crate::auth::keys::KeySet;
use crate::config::Config;

/// Klaim access token. Nama field sengaja pendek karena ikut di setiap request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    /// Slug app pemilik token; inilah yang dicek per route.
    pub aud: String,
    /// App id yang menerbitkan token.
    pub azp: String,
    pub sid: String,
    /// `user` atau `service`.
    pub typ: String,
    pub role: Vec<String>,
    pub scope: Vec<String>,
    /// Snapshot `users.token_version` saat token dibuat.
    pub tv: i32,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
}

/// Kegagalan verifikasi token. Sengaja sempit supaya handler bisa memetakan ke
/// status HTTP tanpa menebak isi pesan error library.
#[derive(Debug, PartialEq, Eq)]
pub enum JwtError {
    Expired,
    BadAudience,
    BadIssuer,
    UnknownKid,
    Invalid,
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            JwtError::Expired => "token kedaluwarsa",
            JwtError::BadAudience => "audience token tidak cocok",
            JwtError::BadIssuer => "issuer token tidak cocok",
            JwtError::UnknownKid => "kid token tidak dikenal",
            JwtError::Invalid => "token tidak valid",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for JwtError {}

/// Tandatangani access token dengan key aktif. `kid` selalu ikut di header
/// supaya verifier downstream bisa memilih kunci dari JWKS.
pub fn sign_access(keys: &KeySet, claims: &Claims) -> Result<String, JwtError> {
    let key = keys.signing_key();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());

    let (encoding_key, _) = key.key_pair();
    encode(&header, claims, encoding_key).map_err(|_| JwtError::Invalid)
}

/// Verifikasi access token untuk satu app (`expected_aud` = `app.slug`).
///
/// `iss` wajib sama dengan `IAM_PUBLIC_URL`, `aud` wajib sama dengan app yang
/// diakses, dan `exp` wajib belum lewat. Kunci dipilih dari `kid` di header,
/// bukan selalu kunci aktif: token yang ditandatangani kunci lama tetap sah
/// selama kunci itu masih hidup di `KeySet`. `kid` asing ditolak lebih dulu,
/// sebelum signature dihitung.
pub fn verify_access(
    config: &Config,
    keys: &KeySet,
    token: &str,
    expected_aud: &str,
) -> Result<Claims, JwtError> {
    let header = decode_header(token).map_err(|_| JwtError::Invalid)?;
    let kid = header.kid.ok_or(JwtError::UnknownKid)?;
    let decoding_key = keys.verifier(&kid).ok_or(JwtError::UnknownKid)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[expected_aud]);
    validation.set_issuer(&[config.iam_public_url.as_str()]);
    validation.set_required_spec_claims(&["exp", "aud", "iss"]);

    let data =
        decode::<Claims>(token, decoding_key, &validation).map_err(|err| match err.kind() {
            ErrorKind::ExpiredSignature => JwtError::Expired,
            ErrorKind::InvalidAudience => JwtError::BadAudience,
            ErrorKind::InvalidIssuer => JwtError::BadIssuer,
            _ => JwtError::Invalid,
        })?;

    Ok(data.claims)
}
