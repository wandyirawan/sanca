use std::io::{IsTerminal, Read};

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};

use crate::auth::password::hash_password;
use crate::config::Config;
use crate::db::{rbac, users};

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
    /// Operasi administratif pada tabel users.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum UserCommand {
    /// Buat user baru. Password dibaca dari stdin, tidak pernah dari argumen.
    Create {
        /// Email user; case-insensitive karena kolomnya citext.
        #[arg(long)]
        email: String,
        /// Tandai bahwa password dikirim lewat stdin (pipe/redirect).
        #[arg(long)]
        password_stdin: bool,
        /// Nama tampilan; boleh kosong.
        #[arg(long, default_value = "")]
        display_name: String,
        /// Beri hak superadmin.
        #[arg(long)]
        superadmin: bool,
    },
}

impl Cli {
    /// Apakah pengguna meminta `healthcheck` alih-alih menjalankan server.
    pub fn is_healthcheck(&self) -> bool {
        matches!(self.command, Some(Command::Healthcheck))
    }
}

/// Jalankan subcommand yang tidak butuh server HTTP.
///
/// Secret (password) hanya dibaca dari stdin: argumen CLI terlihat di `ps` dan
/// tersimpan di riwayat shell, jadi tidak pernah dipakai untuk password.
pub async fn run_user_command(command: &UserCommand) -> anyhow::Result<()> {
    match command {
        UserCommand::Create {
            email,
            password_stdin,
            display_name,
            superadmin,
        } => {
            let config = Config::from_env().map_err(anyhow::Error::msg)?;
            let password = read_password(*password_stdin)?;

            let hash = hash_password(&password, &config.argon2_pepper)
                .context("password ditolak saat hashing")?;

            let database_url = std::env::var("DATABASE_URL")
                .context("DATABASE_URL wajib diisi untuk operasi database")?;
            let pool = sqlx::PgPool::connect(&database_url)
                .await
                .context("gagal terhubung ke database")?;

            if users::by_email(&pool, email)
                .await
                .context("gagal memeriksa email yang sudah ada")?
                .is_some()
            {
                bail!("email {email} sudah terdaftar");
            }

            // Satu transaksi: user dan keanggotaan role superadmin lahir bersama,
            // supaya tidak pernah ada admin dengan `"role": []` di tokennya.
            let mut tx = pool.begin().await.context("gagal memulai transaksi")?;

            let user = users::insert_with_flags(
                &mut *tx,
                email,
                &hash,
                display_name,
                *superadmin,
                config.argon2_pepper_version,
            )
            .await
            .context("gagal menyimpan user")?;

            if *superadmin {
                let role_ditemukan = rbac::assign_system_superadmin(&mut tx, user.id)
                    .await
                    .context("gagal memberi role superadmin")?;
                if !role_ditemukan {
                    // Transaksi dibatalkan oleh drop, jadi tidak ada user tanpa role.
                    bail!("role superadmin app core tidak ditemukan; seed core belum dijalankan?");
                }
            }

            tx.commit().await.context("gagal menyimpan transaksi")?;

            // Hanya id dan email; password maupun hash tidak pernah dicetak.
            println!("user dibuat: {} {}", user.id, user.email);
            if user.is_superadmin {
                println!("superadmin: ya (role superadmin app core)");
            }
            Ok(())
        }
    }
}

/// Baca password dari stdin, buang newline penutup.
///
/// Kalau stdin masih terminal (tidak ada pipe) dan `--password-stdin` tidak
/// diberikan, berhenti dengan pesan jelas daripada menggantung menunggu EOF.
fn read_password(password_stdin: bool) -> anyhow::Result<String> {
    let stdin = std::io::stdin();
    if !password_stdin && stdin.is_terminal() {
        bail!("kirim password lewat stdin, misalnya: ... --password-stdin < password.txt");
    }

    let mut buffer = String::new();
    stdin
        .lock()
        .read_to_string(&mut buffer)
        .context("gagal membaca password dari stdin")?;

    Ok(buffer.trim_end_matches(['\r', '\n']).to_string())
}
