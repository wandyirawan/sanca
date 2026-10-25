use std::io::{IsTerminal, Read};

use crate::auth::password::hash_password;
use crate::config::Config;
use crate::db::apps::{self, AppKind};
use crate::db::{rbac, users};
use crate::domain::apps as domain_apps;
use crate::error::AppError;
use anyhow::{Context, bail};
use clap::{Parser, Subcommand, ValueEnum};

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
    /// Operasi administratif pada tabel apps dan kredensialnya.
    App {
        #[command(subcommand)]
        command: AppCommand,
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

/// Subcommand registry app.
#[derive(Subcommand, Debug)]
pub enum AppCommand {
    /// Daftarkan app baru sekaligus kredensial client pertamanya.
    Create {
        /// Slug app; dipakai sebagai klaim `aud` di setiap token.
        #[arg(long)]
        slug: String,
        /// Nama tampilan app.
        #[arg(long)]
        name: String,
        /// Jenis app, menentukan cara klien memakai token.
        #[arg(long, value_enum)]
        kind: AppKindArg,
    },
    /// Cabut kredensial lama app dan terbitkan pasangan client baru.
    RotateSecret {
        /// Slug app yang kredensialnya dirotasi.
        slug: String,
    },
}

/// Pembungkus `AppKind` supaya clap bisa memvalidasi nilainya.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AppKindArg {
    Web,
    Spa,
    Service,
    Cli,
}

impl From<AppKindArg> for AppKind {
    fn from(value: AppKindArg) -> Self {
        match value {
            AppKindArg::Web => AppKind::Web,
            AppKindArg::Spa => AppKind::Spa,
            AppKindArg::Service => AppKind::Service,
            AppKindArg::Cli => AppKind::Cli,
        }
    }
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

/// Jalankan subcommand registry app.
///
/// Secret client hanya dicetak sekali, saat dibuat. Sesudah itu yang tersimpan
/// di database cuma hash-nya, jadi secret asli memang tidak bisa ditampilkan
/// ulang — pemanggil harus menyimpannya saat itu juga.
pub async fn run_app_command(command: &AppCommand) -> anyhow::Result<()> {
    let config = Config::from_env().map_err(anyhow::Error::msg)?;
    let pool = connect().await?;

    match command {
        AppCommand::Create { slug, name, kind } => {
            // Aturan slug, pencabutan, dan penerbitan kredensial ada di
            // `domain::apps`; CLI hanya mencetak hasilnya. Console memanggil
            // fungsi yang sama, jadi tidak ada dua implementasi yang menyimpang.
            let (app, credential) =
                domain_apps::create_app(&pool, &config, slug, name, AppKind::from(*kind), "")
                    .await
                    .map_err(domain_error)?;

            println!("app dibuat: {} ({}) id {}", app.slug, name, app.id);
            print_credential(&credential.client_id, &credential.client_secret);
            Ok(())
        }
        AppCommand::RotateSecret { slug } => {
            let Some(app) = apps::by_slug(&pool, slug)
                .await
                .context("gagal mencari app")?
            else {
                bail!("app dengan slug {slug} tidak ditemukan");
            };

            let credential = domain_apps::rotate_secret(&pool, &config, app.id)
                .await
                .map_err(domain_error)?;

            println!("secret dirotasi untuk app: {}", app.slug);
            print_credential(&credential.client_id, &credential.client_secret);
            Ok(())
        }
    }
}

/// Pesan CLI untuk kegagalan domain. Variant `AppError` tidak mengimplementasi
/// `Display` karena di HTTP ia dipetakan ke kode JSON, jadi diterjemahkan di sini.
fn domain_error(err: AppError) -> anyhow::Error {
    match err {
        AppError::BadRequest(message) | AppError::Conflict(message) => anyhow::anyhow!("{message}"),
        AppError::NotFound => anyhow::anyhow!("app tidak ditemukan"),
        AppError::Forbidden => anyhow::anyhow!("aksi ini tidak diizinkan"),
        AppError::Unauthorized => anyhow::anyhow!("kredensial database ditolak"),
        AppError::TooManyRequests | AppError::Internal => {
            anyhow::anyhow!("operasi app gagal; periksa log server")
        }
    }
}

/// Cetak kredensial sekali, dengan peringatan bahwa secret tidak bisa dilihat lagi.
fn print_credential(client_id: &str, secret: &str) {
    println!("client_id: {client_id}");
    println!("client_secret: {secret}");
    println!(
        "PERINGATAN: simpan client_secret sekarang. Yang tersimpan di database hanya \
         hash-nya, jadi secret ini tidak bisa ditampilkan lagi."
    );
}

/// Pool database untuk subcommand administratif.
async fn connect() -> anyhow::Result<sqlx::PgPool> {
    let database_url =
        std::env::var("DATABASE_URL").context("DATABASE_URL wajib diisi untuk operasi database")?;

    sqlx::PgPool::connect(&database_url)
        .await
        .context("gagal terhubung ke database")
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
