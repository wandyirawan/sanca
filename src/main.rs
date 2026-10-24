use clap::Parser;

use sanca::cli::{Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Subcommand administratif tidak menyalakan server HTTP, jadi ditangani di
    // sini sebelum startup (yang khusus untuk serve) dipanggil.
    if let Some(Command::User { command }) = &cli.command {
        return sanca::cli::run_user_command(command).await;
    }

    if let Some(Command::App { command }) = &cli.command {
        return sanca::cli::run_app_command(command).await;
    }

    sanca::startup::run(cli).await
}
