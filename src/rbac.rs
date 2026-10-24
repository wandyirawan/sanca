//! RBAC: registry route sebagai satu-satunya sumber kebenaran permission.
//!
//! Modul ini sengaja kecil: `registry` mendaftar route dan permission yang
//! diwajibkannya, `enforce` menegakkannya di middleware, dan `sync` menyalin
//! daftar permission ke database saat boot supaya konsol bisa membacanya.

pub mod enforce;
pub mod registry;
pub mod sync;
