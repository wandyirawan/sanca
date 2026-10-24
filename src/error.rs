//! Error transport yang dipetakan ke respons JSON seragam.
//!
//! Detail internal (pesan sqlx, error crypto) tidak pernah ikut ke klien. Yang
//! dikirim hanya kode pendek dan pesan yang memang aman dibaca pemanggil.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Kegagalan yang boleh muncul di handler HTTP.
#[derive(Debug)]
pub enum AppError {
    /// Tidak ada token, token rusak, aud salah, atau kredensial login salah.
    Unauthorized,
    /// Token sah tapi tipenya tidak cocok untuk route ini (mis. token service).
    Forbidden,
    NotFound,
    /// Input dari klien ditolak; pesannya aman ditampilkan.
    BadRequest(String),
    /// Terlalu banyak percobaan login gagal dalam jendela waktu.
    TooManyRequests,
    /// Kesalahan di sisi kita: jangan pernah bocorkan isinya.
    Internal,
}

impl AppError {
    /// Kode stabil yang dipakai klien untuk bercabang tanpa membaca pesan.
    fn code(&self) -> &'static str {
        match self {
            AppError::Unauthorized => "unauthorized",
            AppError::Forbidden => "forbidden",
            AppError::NotFound => "not_found",
            AppError::BadRequest(_) => "bad_request",
            AppError::TooManyRequests => "too_many_requests",
            AppError::Internal => "internal",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self {
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            AppError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };

        // Pesan sengaja tidak membedakan "email tidak ada" dari "password salah",
        // dan tidak pernah memuat detail database.
        let message = match &self {
            AppError::Unauthorized => "kredensial tidak valid atau sudah kedaluwarsa",
            AppError::Forbidden => "token tidak berlaku untuk aksi ini",
            AppError::NotFound => "resource tidak ditemukan",
            AppError::BadRequest(detail) => detail.as_str(),
            AppError::TooManyRequests => "terlalu banyak percobaan login, coba lagi nanti",
            AppError::Internal => "terjadi kesalahan internal",
        };

        let body = Json(json!({ "error": self.code(), "message": message }));
        (status, body).into_response()
    }
}

/// Semua kegagalan query jadi 500 di mata klien, tapi tetap tercatat di log
/// supaya operator bisa menelusuri penyebabnya.
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!(error = %err, "query database gagal");
        AppError::Internal
    }
}
