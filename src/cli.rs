use clap::{Parser, Subcommand};

/// Sanca — IAM service ringan berbasis Rust + PostgreSQL.
#[derive(Parser, Debug)]
#[command(name = "sanca", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Periksa apakah server yang sedang berjalan merespons endpoint /healthz.
    Healthcheck,
}

impl Cli {
    /// Apakah pengguna meminta `healthcheck` alih-alih menjalankan server.
    pub fn is_healthcheck(&self) -> bool {
        matches!(self.command, Some(Command::Healthcheck))
    }
}
