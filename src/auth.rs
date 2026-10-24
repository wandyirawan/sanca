//! Primitif autentikasi: password (Argon2id), signing key RSA, dan access token.
//!
//! Modul ini tidak tahu HTTP. Handler, cookie, dan refresh token hidup di lane
//! transport; di sini hanya operasi murni yang bisa diuji tanpa server.

pub mod extractor;
pub mod jwt;
pub mod keys;
pub mod password;

pub use jwt::{Claims, JwtError, sign_access, verify_access};
pub use keys::{KeyError, SigningKey};
pub use password::{MIN_PASSWORD_LEN, PasswordError, hash_password, verify_password};
