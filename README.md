# Sanca

IAM service ringan — alternatif kecil untuk Keycloak — ditulis ulang di Rust dengan
PostgreSQL. Satu binary, dua muka: REST API JSON untuk service lain, dan console admin
HTML server-rendered (askama + HTMX + daisyUI, tanpa langkah build CSS).

Nama `sanca` (ular sanca): penjaga gerbang yang senyap.

## Kenapa ada, bukan cuma Keycloak lagi

1. **App sebagai entitas first-class.** Setiap token terikat ke satu app (`aud` + `azp`),
   jadi downstream tahu persis request ini milik app/microservice mana.
2. **RBAC per app.** Role dan permission di-scope `app_id`. `admin` di app Salak berbeda
   dari `admin` di app Kelapa.
3. **Route-gated permission.** Setiap route API punya permission wajib yang dideklarasikan
   di satu registry. Tidak ada permission di `scope` → route tidak bisa di-hit, dan menu
   di console tidak dirender.
4. **Jejak pemanggil.** `audit_events.app_id` + `sessions.app_id` mencatat siapa (user
   atau service), dari app mana, route apa, kapan, status berapa.

## Status project

Belum bisa dipakai sebagai IAM. Yang ada baru kerangka + skema database.

| Bagian | Status |
|---|---|
| Crate Rust (axum 0.8, edition 2024), `/healthz`, tracing, request-id | selesai |
| Skema PostgreSQL 18 (11 tabel: users, apps, sessions, rbac, audit, signing_keys) | selesai |
| Query inti: users, apps + credential, sessions, audit, signing keys, `resolve_scope` | selesai |
| Login/logout/refresh, JWT + JWKS | belum |
| App registry + M2M token (`client_credentials`) | belum |
| RBAC enforcement middleware + registry route | belum |
| Console admin (login, users, apps, RBAC matrix, audit) | belum |
| OAuth2 authorize + PKCE | belum |
| Metrik, OpenAPI, CI, image Docker teruji | belum |

Rencana lengkap per phase, invariant, model data, dan keputusan desain ada di
[`AGENTS.md`](AGENTS.md) — dokumen itu sumber kebenaran, bukan README ini.

## Stack

Rust 1.99.1 (edition 2024) · axum 0.8.9 · tokio 1.54 · sqlx 0.9 (macro, bukan ORM) ·
PostgreSQL 18 · argon2id · jsonwebtoken RS256 · askama 0.16 · HTMX 2 · daisyUI 5
(CSS di-vendor, nol build) · tracing + Grafana Alloy → Loki.

Mold dipakai sebagai linker (lihat `~/.cargo/config.toml`), bukan bagian repo.

## Jalan lokal

```bash
# 1. database + observability (postgres 5433, loki 3100, alloy 12345, grafana 3000)
docker compose up -d db
docker compose --profile obs up -d

# 2. migrasi
export DATABASE_URL=postgres://sanca:sanca@localhost:5433/sanca_dev
sqlx migrate run

# 3. server di 127.0.0.1:8080 dengan auto-reload
make dev

# 4. cek
curl -s localhost:8080/healthz      # {"status":"ok"}
```

Kalau `make dev` bilang `cargo-watch` tidak ada:

```bash
cargo install cargo-watch sqlx-cli --no-default-features -F postgres,rustls --locked
```

### Test

```bash
export DATABASE_URL=postgres://sanca:sanca@localhost:5433/sanca_dev
cargo test        # #[sqlx::test] bikin database sementara sendiri
```

### Build tanpa database

`.sqlx/` di-commit, jadi build di CI tidak perlu DB hidup:

```bash
SQLX_OFFLINE=true cargo build
```

## Struktur singkat

```
src/
  main.rs        parse CLI, panggil startup
  startup.rs     build_app() -> Router (dipakai main DAN test) + serve
  telemetry.rs   init tracing (pretty di dev, JSON di prod)
  config.rs      env -> Config, fail-fast
  cli.rs         subcommand: healthcheck, serve
  api/           transport JSON (sekarang baru health)
  db/            SQL bertipe lewat macro sqlx; tanpa aturan bisnis
migrations/      SQL saja, dijalankan `sqlx migrate run`
tests/           integrasi, termasuk skema & resolve_scope terhadap Postgres nyata
deploy/          konfigurasi loki, alloy, grafana (profil obs)
```

Arah dependency yang wajib dijaga: `api/` → `domain/` → `db/`. `db/` tidak boleh
mengimpor `api/`, dan `api/` tidak merender HTML.

## Konfigurasi

Dibaca dari environment, nama variabelnya saja ada di [`.env.example`](.env.example).
Secret tidak pernah masuk `Cargo.toml`, config file, argumen CLI, atau log.

| Variabel | Default | Keterangan |
|---|---|---|
| `DATABASE_URL` | — | Postgres DSN |
| `IAM_BIND` | `127.0.0.1:8080` | alamat listen |
| `SANCA_ENV` | `dev` | `dev` atau `prod` |
| `SANCA_LOG_FORMAT` | `pretty` | `pretty` atau `json` |
| `SANCA_LOG_DIR` | `/var/log/sanca` | folder file log, rotasi harian, di-tail Alloy |
| `RUST_LOG` | `info` | filter tracing |

## Lisensi

MIT (lihat `LICENSE` bila sudah ditambahkan).
