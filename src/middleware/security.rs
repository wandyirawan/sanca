//! Security header untuk respons console (HTML).
//!
//! CSP sengaja ketat: tanpa `unsafe-inline`, tanpa `unsafe-eval`. Semua skrip
//! dan gaya berasal dari origin sendiri (aset di-serve lewat rust-embed), jadi
//! `script-src 'self'` dan `style-src 'self'` cukup. `frame-ancestors 'none'`
//! melengkapi `X-Frame-Options: DENY`.

use axum::extract::Request;
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;

/// Kebijakan CSP yang dipakai untuk semua respons HTML console.
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
    img-src 'self' data:; font-src 'self' data:; connect-src 'self'; \
    object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'";

/// Tambahkan security header ke respons yang relevan (path console/oauth/assets).
pub async fn security_headers(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    let apply =
        path.starts_with("/console") || path.starts_with("/oauth") || path.starts_with("/assets");

    let mut response = next.run(request).await;

    if apply {
        let headers = response.headers_mut();
        if let Ok(value) = header::HeaderValue::from_str(CSP) {
            headers.insert(header::CONTENT_SECURITY_POLICY, value);
        }
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            header::HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            header::X_FRAME_OPTIONS,
            header::HeaderValue::from_static("DENY"),
        );
        headers.insert(
            header::REFERRER_POLICY,
            header::HeaderValue::from_static("strict-origin-when-cross-origin"),
        );
    }

    response
}
