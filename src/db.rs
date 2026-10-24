//! Lapisan akses data. Semua query SQL tinggal di submodule ini supaya handler
//! tidak pernah menyentuh string SQL langsung.

pub mod rbac;
pub mod users;
