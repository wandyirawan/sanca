use clap::Parser;

use sanca::cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    sanca::startup::run(cli).await
}
