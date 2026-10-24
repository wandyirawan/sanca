# AGENTS.md — Sanca (IAM · Rust + PostgreSQL)

Dokumen ini adalah konteks proyek + rencana implementasi. Baca utuh sebelum menulis kode.
Semua klaim versi di sini sudah diverifikasi ke crates.io / npm registry / Docker registry
pada 2026-10-24.

---

## 1. Apa yang dibangun

Sanca = IAM service (alternatif ringan Keycloak, penerus semangat Mangosteen) ditulis ulang
di Rust dengan PostgreSQL. Satu binary, dua muka:

- **REST API JSON** — dipakai service/microservice lain untuk login, klaim token, ambil
  JWKS, dan (opsional) OAuth2 authorize.
- **Console admin HTML** — server-rendered: askama + HTMX + daisyUI.

Bedanya dengan Mangosteen, dan ini alasan Sanca ada:

1. **App sebagai entitas first-class.** Setiap token terikat ke satu app (`aud` + `azp`),
   jadi downstream tahu persis request ini milik app/microservice mana.
2. **RBAC per app.** Role dan permission di-scope `app_id`. `admin` di app Salak berbeda
   dari `admin` di app Kelapa.
3. **Route-gated permission.** Setiap route API punya permission wajib yang dideklarasikan
   di satu registry. Tidak ada permission di `scope` → route tidak bisa di-hit, dan menu/
   tombol di console tidak dirender.
4. **Jejak pemanggil.** `audit_events.app_id` + `sessions.app_id` mencatat siapa (user/
   service), dari app mana, route apa, kapan, status berapa.

Nama: `sanca` (ular sanca) — penjaga gerbang yang senyap. Nama masih bebas di crates.io
dan github.com/wandyirawan/sanca.

---

## 2. Invariant yang tidak boleh dilanggar

1. **Password di-hash, tidak pernah dienkripsi.** Argon2id satu arah. Tidak ada jalur
   "dekripsi password" di kode mana pun.
2. **Secret hanya dari env.** Tidak ada secret di `Cargo.toml`, config file, argumen CLI,
   atau log. Fail-fast kalau env wajib kosong.
3. **Otorisasi ditegakkan di server.** Menyembunyikan menu/tombol itu UX, bukan keamanan.
   Setiap handler tetap cek `scope` (atau `require_permission`).
4. **Tidak ada permission yang dipakai di kode tanpa terdaftar di registry route.**
   Registry = satu-satunya sumber kebenaran (lihat §5).
5. **Token lintas app ditolak.** Request dengan `aud` != app route → 401, bukan 403.
6. **SQL ditulis tangan, dicek saat compile** lewat macro sqlx. Tidak ada ORM, tidak ada
   query string yang dirakit runtime.
7. **Migrasi hanya lewat `sqlx migrate`.** Tidak ada DDL manual di psql.

---

## 3. Stack (terverifikasi)

| Layer | Pilihan | Versi |
|---|---|---|
| Rust | edition 2024, rustc | 1.99.1 |
| HTTP | axum | 0.8.9 |
| Async | tokio | 1.54.1 |
| DB | sqlx (postgres, macros, uuid, time, runtime-tokio, tls-rustls) | 0.9.0 |
| Migrasi | sqlx-cli | 0.9.x |
| Password | argon2 (Argon2id) | 0.6.0 |
| JWT | jsonwebtoken (RS256) | 11.1.0 |
| Middleware | tower-http (trace, cors, request-id, limit) | 0.7.1 |
| Template | askama | 0.16.1 |
| UI | HTMX | 2.0.11 |
| UI CSS | daisyUI, self-hosted full CSS (tanpa build Tailwind) | 5.7.50 — 1.14 MB raw / 63 kB gzip |
| OpenAPI | utoipa (+ utoipa-axum) | 6.0.0 |
| Validasi | validator | 0.21.0 |
| Error | thiserror | 2.0.21 |
| Log | tracing + tracing-subscriber (json, env-filter) | 0.1.44 / 0.3.23 |
| Log → tracing bridge OTel (opsional, P7) | tracing-opentelemetry + opentelemetry-otlp | 0.34.0 / 0.33.1 |
| Metrik (opsional, P7) | metrics + metrics-exporter-prometheus | 0.24.6 / 0.18.3 |
| ID | uuid v7 | 1.29.0 |
| Secret wrapper | secrecy + zeroize | latest |
| DB | PostgreSQL | 18 |
| Runtime image | gcr.io/distroless/cc-debian12:nonroot | (verified exists) |
| CLI | clap (derive) | 4.6.7 |
| Cookie/header helper | axum-extra (cookie) | 0.12.6 |
| Embed static assets | rust-embed | 8.13.0 |
| Error di lapisan CLI/bootstrap | anyhow | 1.x |
| Serialisasi | serde + serde_json | 1.0.229 |

**Jangan** memakai `askama_axum` — deprecated sejak askama 0.13. Render manual ke
`axum::response::Html`.

Konteks query: **sqlc di Go ≈ sqlx macro di Rust.** sqlc generate kode dari file query;
sqlx tidak generate file, tapi macro `query!`/`query_as!` memvalidasi SQL + menurunkan tipe
Rust saat compile (butuh `DATABASE_URL` atau cache `.sqlx/`). Kalau tetap mau workflow
codegen ala sqlc, padanan literalnya `cornucopia` 1.0.1 (generate crate dari `.sql`), tapi
anotasinya `--! nama_query` + `:param`, bukan `-- name: X :one` + `$1`.

---

## 4. Struktur direktori

Aturan arah dependency (tidak boleh ada siklus):

```
api/  console/        transport: parse request, validasi bentuk, render/encode
      ↓
domain/               use-case: aturan bisnis, transaksi, urutan langkah
      ↓
db/  auth/  rbac/     primitif: SQL bertipe, kripto/token, registry+enforcement
      ↓
config/ state/ error/ infrastruktur
```

- `db/` tidak boleh `use crate::api` atau `crate::console`. Hanya SQL + tipe.
- `domain/` boleh memanggil `db/`, `auth/`, `rbac/`. Tidak merender HTML.
- `api/` dan `console/` tidak saling import. Keduanya panggil `domain/`.
- `templates/` hanya boleh berisi tampilan; tidak ada keputusan otorisasi selain
  `can(...)` (yang datanya sudah dihitung server).

```
~/Sandbox/sanca/
├── AGENTS.md                        # dokumen ini = konteks + rencana
├── Cargo.toml                       # [lib] sanca (src/lib.rs) + [[bin]] sanca (src/main.rs)
├── Cargo.lock                        # di-commit (ini aplikasi, bukan library)
├── rust-toolchain.toml              # pin 1.99.1 + components: rustfmt, clippy
├── .env.example                     # nama variabel saja, tanpa nilai
├── .gitignore                        # /target, .env, *.pem
├── .dockerignore                     # /target, .git, .env — .sqlx HARUS ikut
├── Makefile                          # db, dev, test, prepare, migrate, docker
├── Dockerfile                        # 2 stage: chef builder → distroless/cc
├── docker-compose.yml                # profil db (dev) + app (prod-like)
├── .sqlx/                            # cache query offline, hasil `make prepare`, di-commit
├── migrations/                       # default sqlx-cli, di root crate (jangan dipindah)
│   ├── 0001_init.sql                 # users, apps, sessions, rbac, audit, signing_keys
│   └── 0002_seed_core_app.sql        # app `core` + role superadmin
├── sql/                              # SQL panjang → query_file_as! / include_str!
│   └── rbac_resolve_scope.sql        # join scope; lebih nyaman diedit sebagai .sql
├── assets/
│   ├── app.css                       # CSS tulisan tangan (layout, tweak kecil) — di-commit
│   └── vendor/                       # dependency pihak ketiga, di-vendor (bukan artefak build)
│       ├── daisyui.css               # 5.7.50, 1.14 MB raw / 63 kB gzip
│       └── htmx.min.js               # 2.0.11, 52 kB
├── templates/                        # askama, compile-time
│   ├── layout.html                   # shell: sidebar + navbar daisyUI + #toast
│   ├── login.html                    # form biasa (bukan HTMX), CSRF token
│   ├── dashboard.html                # kartu statistik, poll 30s
│   ├── partials/
│   │   ├── nav.html                  # menu dibungkus {% if can("...") %}
│   │   ├── toast.html                # target out-of-band (hx-swap-oob)
│   │   ├── pagination.html
│   │   └── error.html                # fragment error untuk respons HTMX
│   ├── users/
│   │   ├── list.html                 # halaman penuh (shell tabel + filter)
│   │   ├── rows.html                 # fragment <tr> untuk hx-get search/paging
│   │   ├── form.html                 # modal create/edit (dialog daisyUI)
│   │   └── detail.html               # modal detail + daftar role/atribut
│   ├── apps/
│   │   ├── list.html
│   │   ├── rows.html
│   │   ├── form.html
│   │   └── credentials.html          # client_id/secret sekali tampil + tombol rotate
│   ├── rbac/
│   │   ├── roles.html
│   │   ├── permissions.html          # katalog, permission is_system read-only
│   │   └── matrix.html               # grid role × permission (checkbox)
│   └── audit/
│       ├── list.html
│       └── rows.html
├── src/
│   ├── main.rs                       # 5-10 baris: parse CLI, panggil startup::run
│   ├── lib.rs                        # `pub mod ...` supaya tests/ bisa import crate
│   ├── startup.rs                    # build_app() -> Router + serve(): dipakai main DAN tests
│   ├── telemetry.rs                  # init tracing (EnvFilter, fmt/json), dipakai boot & test
│   ├── config.rs                     # env → Config (SecretString), fail-fast, SANCA_ENV
│   ├── state.rs                      # AppState { pool, cfg, signing, registry }
│   ├── error.rs                      # AppError → IntoResponse: JSON *atau* fragment HTML
│   ├── cli.rs                        # clap subcommand: migrate | app | key | healthcheck
│   ├── domain/                       # use-case / aturan bisnis (dulu bernama app/)
│   │   ├── auth.rs                   # login, refresh (rotasi), logout, buat sesi
│   │   ├── users.rs                  # create/update/disable, ganti password, atribut
│   │   ├── apps.rs                   # daftar app, generate/rotate client secret
│   │   └── rbac.rs                   # assign/revoke role, anti-escalation, is_system guard
│   ├── db.rs                          # `pub mod users; pub mod apps; ...` (gaya 2018+, tanpa mod.rs)
│   ├── db/                            # SQL bertipe, tanpa aturan bisnis
│   │   ├── users.rs                  # create, by_email, list(+filter/paging), update
│   │   ├── apps.rs
│   │   ├── rbac.rs                   # roles/permissions CRUD + resolve_scope()
│   │   ├── sessions.rs               # create, by_refresh_hash, revoke, revoke_all
│   │   ├── audit.rs                  # insert, list (filter app/actor/waktu)
│   │   └── keys.rs                   # signing_keys: insert, list active, retire
│   ├── auth.rs                        # deklarasi submodule auth
│   ├── auth/
│   │   ├── password.rs               # argon2id + pepper (pepper_version)
│   │   ├── jwt.rs                    # sign/verify RS256, validasi aud + tv
│   │   ├── keys.rs                   # precedence env→file→generate(dev), rotate
│   │   └── extractor.rs              # AuthUser, AuthApp, RequirePermission
│   ├── rbac.rs                        # deklarasi submodule rbac
│   ├── rbac/
│   │   ├── registry.rs               # const ROUTES — sumber kebenaran permission
│   │   ├── enforce.rs                # middleware MatchedPath → permission → 403
│   │   └── sync.rs                   # registry → tabel permissions (is_system)
│   ├── api.rs                         # router API + layer (trace, request-id, limit)
│   ├── api/                          # transport JSON, satu file per area
│   │   ├── auth.rs                   # POST /api/auth/{login,refresh,logout}
│   │   ├── token.rs                  # POST /api/oauth/token (client_credentials)
│   │   ├── users.rs
│   │   ├── apps.rs
│   │   ├── rbac.rs
│   │   ├── audit.rs
│   │   ├── me.rs                     # GET /api/auth/me → {sub,app,roles,scope}
│   │   ├── jwks.rs                   # GET /.well-known/jwks.json  ← core
│   │   └── health.rs                 # GET /healthz
│   ├── console.rs                     # router console + cookie session + CSRF
│   ├── console/                      # transport HTML
│   │   ├── views.rs                  # struct askama (ListCtx, RowCtx, NavCtx, ...)
│   │   ├── helpers.rs                # can(perm), fmt_dt(), csrf_field()
│   │   └── pages/
│   │       ├── login.rs
│   │       ├── dashboard.rs
│   │       ├── users.rs
│   │       ├── apps.rs
│   │       ├── rbac.rs
│   │       └── audit.rs
│   ├── middleware.rs                  # deklarasi submodule middleware
│   └── middleware/
│       ├── audit.rs                  # tulis audit_events (app_id dari azp)
│       ├── ratelimit.rs              # throttle login per email+IP
│       └── csrf.rs                   # validasi token form console
├── tests/                            # integrasi (pakai crate `sanca` dari lib.rs)
│   ├── api_auth.rs                   # login → token → refresh rotasi → logout
│   ├── api_rbac.rs                   # matriks 401 (aud salah) vs 403 (scope kurang)
│   ├── registry_guard.rs             # semua permission string ada di ROUTES
│   └── console_nav.rs                # nav menyusut sesuai scope
└── docs/
    ├── adr/0001-postgres-sqlx.md     # kenapa Postgres + sqlx, bukan SQLite/cornucopia
    ├── adr/0002-route-permission-registry.md
    └── runbook.md                    # rotasi key/secret, restore, migrasi, rollback
```

### Kesesuaian dengan idiom Rust (hasil review)

Yang **sudah** idiomatic dan jangan diubah:

- `src/lib.rs` + `src/main.rs` — pola resmi untuk aplikasi yang punya integration test
  (`tests/` meng-import crate lewat lib).
- Layer-first (`api/`, `domain/`, `db/`) di dalam satu crate — ini pola yang dipakai
  buku/literatur Rust aplikasi (bukan pola `models/` + `handlers/` ala framework dinamis).
  Organisasi per-fitur baru masuk akal kalau crate sudah > 20k baris.
- `error.rs` dengan `thiserror` + `impl IntoResponse` — kanonik.
- `config.rs` typed config dari env, `state.rs` sebagai `AppState` di `Router::with_state` —
  kanonik.
- `templates/` dan `assets/` di luar `src/` — benar untuk askama (path dihitung dari crate
  root, template di-*compile* jadi kode, bukan dibaca saat runtime).
- `tests/` di root, bukan `src/tests/`.

Yang **diperbaiki** dari draft sebelumnya:

1. `app/` → `domain/`. Nama `app` rawan ketuker dengan `AppState`/`app.rs`; `domain`
   menyatakan isinya (aturan bisnis) dan sejalan dengan penamaan di literatur Rust.
2. **Tanpa `mod.rs`.** Gaya Rust 2018+: `rbac.rs` + `rbac/` sebagai saudara. `mod.rs` masih
   valid tapi bukan gaya yang dipakai crate modern.
3. **Tambah `startup.rs`.** Wajib: `build_app() -> Router` dipakai `main` *dan* `tests/`.
   Tanpa ini, test integrasi harus menduplikasi wiring router.
4. **Tambah `telemetry.rs`.** Init `tracing` dipakai boot dan test; jangan ditulis di `main`.
5. **`migrations/` dipindah ke root crate.** `sqlx-cli` default-nya `./migrations`; kalau
   ditaruh di `sql/migrations` setiap perintah butuh `--source`. Ikut konvensi = nol flag.
6. **Aset & migrasi di-embed.** `rust-embed` untuk `assets/vendor/*`, dan
   `sqlx::migrate!("./migrations")` untuk migrasi. Efeknya image distroless cukup berisi
   satu file binary — tidak ada `COPY` template/asset/migrasi, tidak ada path yang bisa
   hilang saat deploy.
7. **Subcommand pakai `clap` derive** (`cli.rs`), bukan parsing `std::env::args` manual.
   Binary tetap satu; jangan dipecah ke `src/bin/` kecuali benar-benar ada >1 executable.
8. **Tanpa Tailwind / bundler.** Keputusan sadar: Tailwind standalone binary berukuran
   **106,6 MB** (release v4.3.3 `tailwindcss-linux-x64`), dan menempatkannya di Dockerfile
   berarti menambah satu layer besar + waktu build, hanya untuk mengecilkan CSS dari 1,14 MB
   → puluhan kB. Untuk console internal, full `daisyui.css` yang di-gzip 63 kB lebih murah
   secara total (tidak ada tool, tidak ada langkah manual, tidak ada artefak build di git).
   Kalau suatu saat butuh utility Tailwind, lihat ADR 0002 untuk jalur yang sudah ditimbang.

### Resep menambah satu fitur (urutan wajib)

1. `migrations/000N_*.sql` → `make migrate`
2. `src/db/<area>.rs` — fungsi query bertipe (`query_as!`)
3. `src/domain/<area>.rs` — use-case + validasi bisnis
4. `src/rbac/registry.rs` — tambah `RouteDef` (permission + audit_action)
5. `src/api/<area>.rs` — handler tipis + daftarkan route di router
6. `templates/<area>/` — `list.html` (halaman) + `rows.html` (fragment) + `form.html`
7. `src/console/pages/<area>.rs` — view + handler HTML
8. `tests/` — E2E minimal (200 untuk yang berhak, 403 untuk yang tidak)
9. `make prepare` (refresh `.sqlx`) → `make fmt clippy test` → commit

Tanpa langkah 4, route baru akan ditolak middleware (fail-closed 500) — itu disengaja.

---

## 5. Route ↔ permission registry (inti permintaan "kalau nggak ada di route, nggak muncul")

Satu tabel statis di kode, dipakai empat tempat sekaligus:

```rust
// src/rbac/registry.rs
pub enum AppScope { Public, AnyApp, CoreOnly }

pub struct RouteDef {
    pub method: Method,
    pub path: &'static str,                 // template axum, mis. "/api/users/{id}"
    pub permission: Option<&'static str>,   // None = publik (login, jwks, health)
    pub scope: AppScope,
    pub audit_action: Option<&'static str>,
}

pub const ROUTES: &[RouteDef] = &[
    RouteDef::public(GET,  "/healthz"),
    RouteDef::public(GET,  "/.well-known/jwks.json"),           // ← CORE, selalu ada
    RouteDef::public(POST, "/api/auth/login"),
    RouteDef::public(POST, "/api/auth/refresh"),
    RouteDef::public(POST, "/api/oauth/token"),                 // client_credentials
    RouteDef::protected(GET,  "/api/auth/me",       "auth:me"),
    RouteDef::protected(GET,  "/api/users",         "user:read"),
    RouteDef::protected(POST, "/api/users",         "user:write"),
    RouteDef::protected(GET,  "/api/users/{id}",    "user:read"),
    RouteDef::protected(PATCH,"/api/users/{id}",    "user:write"),
    RouteDef::protected(GET,  "/api/apps",          "app:read"),
    RouteDef::protected(POST, "/api/apps",          "app:write"),
    RouteDef::protected(GET,  "/api/roles",         "role:read"),
    RouteDef::protected(POST, "/api/roles",         "role:write"),
    RouteDef::protected(GET,  "/api/audit",         "audit:read"),
    // console
    RouteDef::protected(GET,  "/console/users",     "user:read"),
    RouteDef::protected(GET,  "/console/apps",      "app:read"),
    RouteDef::protected(GET,  "/console/rbac",      "role:read"),
    RouteDef::protected(GET,  "/console/audit",     "audit:read"),
];
```

Empat konsumen registry:

1. **Enforcement** — middleware pakai `axum::extract::MatchedPath` (template, bukan URL
   mentah) untuk lookup `RouteDef`, lalu bandingkan `permission` dengan `scope` claim.
   Tidak ada permission → 403 JSON (API) atau fragment error (console).
2. **Sinkronisasi katalog** — saat boot, `rbac::sync` melakukan `INSERT ... ON CONFLICT DO
   NOTHING` ke tabel `permissions` untuk app `core`, semua dengan `is_system = true`.
   Jadi console bisa menampilkan daftar permission tanpa hardcode di template, dan
   permission sistem tidak bisa dihapus admin.
3. **Visibilitas console** — helper askama `can(perm)` membaca `scope` sesi aktif. Menu di
   `partials/nav.html` dibungkus `{% if can("app:read") %}`; tombol create/edit juga.
   Route yang tidak dimiliki user **tidak dirender sama sekali** di nav (bukan disabled).
4. **Dokumentasi** — `/docs` (utoipa) menampilkan `required scope` per endpoint, diturunkan
   dari registry yang sama sehingga tidak pernah drift.

Endpoint bantu untuk frontend: `GET /api/auth/me` balikin `{sub, app, roles, scope}` supaya
SPA bisa menyembunyikan menu dengan logika yang sama.

Aturan turunan:
- Permission yang tidak ada di registry **tidak boleh** dipakai di handler. Ada test yang
  memindai registry vs string permission yang dipakai (grep-level assertion di test).
- Route baru wajib menambah entri registry; tanpa entry, middleware menolak dengan 500
  "unregistered route" (fail-closed, jangan default allow).

---

## 6. Model data (PostgreSQL 18)

```sql
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE user_status AS ENUM ('active', 'disabled', 'pending');
CREATE TYPE app_kind    AS ENUM ('web', 'spa', 'service', 'cli');
CREATE TYPE actor_type  AS ENUM ('user', 'service', 'system');

CREATE TABLE users (
    id             uuid PRIMARY KEY,
    email          citext UNIQUE NOT NULL,
    password_hash  text   NOT NULL,
    pepper_version smallint NOT NULL DEFAULT 1,
    display_name   text   NOT NULL DEFAULT '',
    status         user_status NOT NULL DEFAULT 'active',
    is_superadmin  boolean NOT NULL DEFAULT false,
    token_version  integer NOT NULL DEFAULT 0,   -- bump = revoke semua akses instan
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_attributes (
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key        text NOT NULL,
    value      jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
);

CREATE TABLE apps (
    id               uuid PRIMARY KEY,
    slug             text UNIQUE NOT NULL,        -- klaim `aud`
    name             text NOT NULL,
    description      text NOT NULL DEFAULT '',
    kind             app_kind NOT NULL DEFAULT 'web',
    redirect_uris    text[] NOT NULL DEFAULT '{}',
    access_ttl_secs  integer NOT NULL DEFAULT 900,
    refresh_ttl_secs integer NOT NULL DEFAULT 2592000,
    is_active        boolean NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE app_credentials (
    id                 uuid PRIMARY KEY,
    app_id             uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    client_id          text UNIQUE NOT NULL,
    client_secret_hash text NOT NULL,
    pepper_version     smallint NOT NULL DEFAULT 1,
    name               text NOT NULL DEFAULT 'default',
    last_used_at       timestamptz,
    revoked_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON app_credentials (app_id);

CREATE TABLE sessions (
    id           uuid PRIMARY KEY,                -- klaim `sid`
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id       uuid NOT NULL REFERENCES apps(id),
    refresh_hash text NOT NULL UNIQUE,
    user_agent   text NOT NULL DEFAULT '',
    ip           inet,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON sessions (user_id);
CREATE INDEX ON sessions (app_id);
CREATE INDEX ON sessions (expires_at);

CREATE TABLE roles (
    id          uuid PRIMARY KEY,
    app_id      uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    key         text NOT NULL,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    is_system   boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (app_id, key)
);

CREATE TABLE permissions (
    id          uuid PRIMARY KEY,
    app_id      uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    key         text NOT NULL,
    name        text NOT NULL,
    description text NOT NULL DEFAULT '',
    is_system   boolean NOT NULL DEFAULT false,   -- dari registry, tidak bisa dihapus
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (app_id, key)
);

CREATE TABLE role_permissions (
    role_id       uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id uuid NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    uuid NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_by uuid REFERENCES users(id),
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE audit_events (
    id             bigserial PRIMARY KEY,
    occurred_at    timestamptz NOT NULL DEFAULT now(),
    app_id         uuid REFERENCES apps(id),
    app_slug       text NOT NULL,
    actor_type     actor_type NOT NULL,
    actor_user_id  uuid REFERENCES users(id),
    actor_label    text NOT NULL DEFAULT '',
    session_id     uuid,
    action         text NOT NULL,
    resource_type  text NOT NULL DEFAULT '',
    resource_id    text NOT NULL DEFAULT '',
    permission_key text,
    method         text NOT NULL DEFAULT '',
    path           text NOT NULL DEFAULT '',
    status_code    integer,
    ip             inet,
    user_agent     text NOT NULL DEFAULT '',
    request_id     text NOT NULL DEFAULT '',
    metadata       jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ON audit_events (app_id, occurred_at DESC);
CREATE INDEX ON audit_events (actor_user_id, occurred_at DESC);
CREATE INDEX ON audit_events (occurred_at DESC);

-- DB hanya menyimpan public key. Private key hidup di env/file (lihat §7).
CREATE TABLE signing_keys (
    kid        text PRIMARY KEY,
    alg        text NOT NULL DEFAULT 'RS256',
    public_pem text NOT NULL,
    is_active  boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz
);
```

**Klaim access token** (TTL 900 detik):

```json
{
  "iss": "https://iam.internal",
  "sub": "<user_id | client_id>",
  "aud": "<app.slug>",
  "azp": "<app_id>",
  "sid": "<session_id>",
  "typ": "user | service",
  "role": ["admin"],
  "scope": ["user:read", "app:read"],
  "tv": 0,
  "jti": "<uuid>",
  "iat": 1760000000, "exp": 1760000900
}
```

`scope` di-resolve sekali saat token diterbitkan (join user_roles → role_permissions →
permissions untuk `app_id` tsb). `tv` (`token_version`) dipakai untuk revocation instan:
kalau `users.token_version` > `tv` di token, tolak. Cek `tv` hanya di endpoint yang
sensitif (mutasi role/permission, logout-all, ganti password), bukan di semua request,
supaya tidak ada query DB per request.

---

## 7. Kredensial: hash vs enkripsi, semua key dari env

**Password tidak pernah dienkripsi.** Enkripsi reversible — bocor kuncinya, semua password
terbuka. Argon2id satu arah: server hanya memverifikasi.

| Kredensial | Perlakuan | Alasan |
|---|---|---|
| `users.password_hash` | argon2id m=19456 KiB, t=2, p=1, salt 16B acak, PHC string | sengaja lambat |
| `app_credentials.client_secret_hash` | secret 32B acak (base64url), simpan `SHA-256(pepper‖secret)` | entropi 256-bit, KDF lambat tidak menambah keamanan |
| `sessions.refresh_hash` | refresh 32B acak, simpan `SHA-256(token)` | dipakai tiap refresh, harus murah |
| JWT private key | RSA-3072 PEM di env/file 0600 | jangan di tabel yang di-backup sembarangan |

**Pepper** (`ARGON2_PEPPER`, base64 32B) disuntik sebagai parameter `secret` argon2
(`Argon2::new_with_secret`). `pepper_version` di tabel memungkinkan rotasi bertahap:
verifikasi pakai versi lama, rehash saat login sukses berikutnya. Pepper hilang = semua
password tidak bisa diverifikasi → wajib backup di tempat terpisah.

**Env** (dibaca `src/config.rs`, fail-fast, tanpa default hardcoded untuk secret):

```
DATABASE_URL=postgres://sanca:sanca@localhost:5433/sanca_dev
IAM_BIND=127.0.0.1:8080
IAM_PUBLIC_URL=https://iam.internal          # klaim iss, wajib sama di semua app
IAM_ALLOWED_ORIGINS=http://localhost:8080
SANCA_ENV=dev                                # dev | prod

JWT_KID=sanca-2026-10
JWT_PRIVATE_KEY_PEM=                         # base64 PEM, prioritas tertinggi
JWT_PRIVATE_KEY_PATH=                        # alternatif, wajib chmod 600
ARGON2_PEPPER=
ARGON2_PEPPER_VERSION=1
CLIENT_SECRET_PEPPER=
SESSION_COOKIE_KEY=
SANCA_MASTER_KEY=                            # opsional: envelope XChaCha20-Poly1305
```

Precedence signing key: `JWT_PRIVATE_KEY_PEM` → `JWT_PRIVATE_KEY_PATH` → generate baru
**hanya di `SANCA_ENV=dev`** (dengan warning). `SANCA_ENV=prod` tanpa key = exit 1.

Aturan: `.env` gitignored + `chmod 600`; `.env.example` hanya nama variabel; secret dibungkus
`secrecy::SecretString` (Debug = `***`); buffer kunci `zeroize` setelah dipakai; secret
tidak pernah lewat argv (kelihatan di `ps`).

Generate sekali:

```bash
mkdir -p ~/.config/sanca && chmod 700 ~/.config/sanca
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out ~/.config/sanca/jwt.pem
chmod 600 ~/.config/sanca/jwt.pem
head -c 32 /dev/urandom | base64   # ARGON2_PEPPER
head -c 32 /dev/urandom | base64   # CLIENT_SECRET_PEPPER
head -c 32 /dev/urandom | base64   # SESSION_COOKIE_KEY
```

---

## 8. JWKS (core, bukan fitur tambahan)

`GET /.well-known/jwks.json` wajib ada sejak Phase 2 dan tidak boleh butuh autentikasi.

- Isi: semua key dengan `retired_at IS NULL`, bentuk JWK RS256 (`kty`, `use: "sig"`,
  `alg: "RS256"`, `kid`, `n`, `e`). Cache-Control `public, max-age=300`.
- Signature: `kid` di header JWT harus ketemu di JWKS; verifier downstream menolak token
  dengan `kid` tak dikenal.
- Rotasi: `sanca key rotate` → generate key baru, tulis baris baru di `signing_keys`
  (public), `is_active = true`; key lama tetap dipublish sampai token terlama expired
  (≤15 menit) baru `retired_at` diisi. Semua service downstream tidak perlu restart,
  cukup re-fetch JWKS (max-age 300 dtk).
- Test wajib: token dari key lama masih valid setelah rotasi, dan hilang dari JWKS setelah
  retire; `kid` palsu → 401.

---

## 9. Observability: log, audit, metrik (tiga hal berbeda, jangan dicampur)

| | Log | Audit (`audit_events`) | Metrik |
|---|---|---|---|
| Pertanyaan | "kenapa request ini gagal?" | "siapa melakukan apa, kapan" | "seberapa sering/lama?" |
| Penyimpanan | stdout → Loki | tabel Postgres | scrape Prometheus |
| Retensi | pendek (30 hari) | panjang (kebijakan) | pendek, agregat |
| Sumber | `tracing` | ditulis `domain/` saat aksi sukses | counter/histogram |
| Boleh hilang? | ya, best-effort | tidak (bagian dari kontrak produk) | ya |

Aturan: log **tidak pernah** jadi sumber kebenaran audit, dan audit **tidak** mencatat pesan
error internal (itu tugas log). Keduanya ditulis dari titik kode yang berbeda.

### Stack logging

- `tracing` 0.1.44 + `tracing-subscriber` 0.3.23 (feature `env-filter`, `json`, `fmt`).
  Sudah masuk sejak Phase 0 — `src/telemetry.rs`.
- **Dev**: format `pretty` + ANSI. **Prod**: JSON satu baris per event ke stdout.
  Switch via env `SANCA_LOG_FORMAT=pretty|json` (bukan secret, boleh di env).
- Filter via `RUST_LOG`, default `info`, dengan override per-target:
  `RUST_LOG=info,sanca::db=debug,tower_http=warn`.
- OTel (opsional, Phase 7): `tracing-opentelemetry` 0.34.0 + `opentelemetry-otlp` 0.33.1
  (+ `opentelemetry` 0.33.1). Hanya dipasang kalau ada collector; tanpa collector, stdout
  JSON → Alloy/Promtail → Loki sudah cukup. Jangan bikin Sanca bergantung pada collector.
- Metrik (opsional, Phase 7): `metrics` 0.24.6 + `metrics-exporter-prometheus` 0.18.3 di
  `GET /metrics` (bind terpisah atau dibatasi permission `metrics:read`).

### Skema field log (JSON) — konsisten, biar bisa di-query di Loki

```
ts          RFC3339
level       info|warn|error
target      modul, mis. "sanca::api::auth"
msg         pesan singkat
request_id  dari tower-http RequestIdLayer (juga dikirim balik sebagai x-request-id)
trace_id    kalau OTel aktif (W3C traceparent diterima/diteruskan)
method      GET/POST/...
path        MatchedPath (template, mis. /api/users/{id}) — jangan URL mentah
status      kode HTTP
latency_ms  durasi
app_slug    aud/azp app pemanggil
actor_type  user|service|system
actor_id    user_id atau client_id
session_id  sid
error_kind  enum internal (bukan pesan SQL mentah)
```

Dua contoh query Loki yang harus bisa dijawab tanpa tebak-tebakan:
`{app="sanca"} |= "error" | json | status > 499 | line_format "{{.path}} {{.app_slug}}"`
dan `{app="sanca"} | json | app_slug="salak" | latency_ms > 500`.

### Larangan keras di log

- Jangan pernah: password, `Authorization`/`Cookie` header, access/refresh token,
  `client_secret`, isi `user_attributes` yang berpotensi PII, body request
  `/api/auth/login` dan `/api/oauth/token`.
- Jangan log raw SQL + parameter binding untuk query yang menyentuh kredensial.
- Wrapper secret pakai `secrecy::SecretString` (Debug = `***`) — ini yang mencegah
  kebocoran lewat `{:?}` di struct.
- Pesan error internal disimpan sebagai `error_kind` (enum) + `display` di log level
  `error`; response ke klien tetap generik.
- `tower_http::trace::TraceLayer` jangan dibuat log header/body; cukup span + status.

### Struktur span

```
http.request  {method, path, request_id}          ← root, dibuat TraceLayer
  auth.verify {app_slug, actor_id, ok}            ← extractor
  rbac.check  {permission, ok}                    ← enforce middleware (debug level)
  db.query    {op}                                ← level debug; JANGAN span per row
```
Span `db.query` sengaja `debug`: di `info` dia menghasilkan noise dan biaya. Error tetap
tercatat via `error!` di layer handler.

---

## 10. Phase plan

**Phase 0 — Bootstrap (½ hari)**
- `cargo new sanca --vcs git` (edition 2024), `.gitignore` (.env, target/), `.env.example`.
- Cargo.toml sesuai §3; `[profile.release] lto="thin"`, `strip=true`, `panic="abort"`.
- `docker-compose.yml` profil `db` (postgres:18, port 5433, healthcheck pg_isready).
- `src/main.rs`: `/healthz`, tracing-subscriber, TraceLayer + RequestIdLayer.
- Makefile + Dockerfile (§10, §11).
- `cargo install cargo-watch sqlx-cli --no-default-features -F postgres,rustls`.
- Verifikasi: `make db`, `make dev` (cargo watch nyala), `curl :8080/healthz` = ok.

**Phase 1 — Schema + query layer (1–1.5 hari)**
- `sqlx migrate add -r init` → DDL §6; `sqlx migrate add -r seed_core` → app `core`,
  role `superadmin`, permission sistem dari registry (lihat Phase 4 untuk sync).
- Modul `src/db/*` dengan `query!`/`query_as!`; `#[sqlx::test]` untuk test DB nyata.
- `cargo sqlx prepare` → commit `.sqlx/`; Makefile target `prepare`.
- Verifikasi: `SQLX_OFFLINE=true cargo test` hijau tanpa DB; `resolve_scope(user, app)`
  hanya mengembalikan permission app tsb.

**Phase 2 — Auth core + JWKS (1.5 hari)**
- `auth/password.rs` (argon2id + pepper, tolak < 12 char), `auth/keys.rs` (load/generate,
  precedence env), `auth/jwt.rs` (sign/verify, validasi `aud`), `api/jwks.rs`.
- `POST /api/auth/login` (email + password + app_slug) → access + refresh; refresh rotasi;
  `POST /api/auth/logout`; `GET /api/auth/me`.
- `auth/extractor.rs`: `AuthUser`, `AuthApp`, `RequirePermission(&'static str)`.
- Rate limit login: 5 gagal / 5 menit per email+IP → 429.
- Verifikasi: decode token (aud/azp/scope benar); refresh lama setelah rotasi → 401;
  JWKS `kid` cocok; curl tanpa token → 401.

**Phase 3 — App registry + M2M (1 hari)**
- `POST /api/oauth/token` grant `client_credentials` (Basic auth) → `typ=service`.
- CLI: `sanca app create --slug salak --kind service` (print client_id + secret sekali),
  `sanca app rotate-secret <slug>`, `sanca key rotate`.
- Verifikasi: token service `aud=salak` dipakai ke route app lain → 401.

**Phase 4 — RBAC + route registry (1.5 hari)**
- `rbac/registry.rs` (const ROUTES), `rbac/enforce.rs` (middleware pakai MatchedPath),
  `rbac/sync.rs` (INSERT ON CONFLICT ke `permissions`, `is_system=true`).
- CRUD role/permission/assign; anti-escalation: tidak boleh grant permission yang tidak
  dimiliki pemberi (kecuali superadmin); role `is_system` tidak bisa dihapus.
- Helper askama `can(perm)` + `partials/nav.html` bergantung pada scope.
- Test: user `user:read` → `POST /api/users` 403; route tanpa registry → 500 fail-closed;
  assertion bahwa semua `permission` string di handler ada di ROUTES.
- Verifikasi: `GET /api/auth/me` mengembalikan scope; menu console menyusut sesuai user.

**Phase 5 — Console HTMX + daisyUI (2–3 hari)**
- CSS: `assets/vendor/daisyui.css` (vendored, full build) + `assets/app.css` (tangan).
  Di-serve lewat `rust-embed` + `CompressionLayer` (gzip → ~63 kB). **Nol langkah build.**
- Halaman: login (form biasa, cookie httpOnly SameSite=Lax), dashboard (poll 30s), users
  (search delay 300ms, row swap `hx-target="closest tr"`), apps (+ panel rotate secret),
  RBAC matrix role×permission, audit (filter app/actor/waktu, pagination cursor).
- Semua menu/tombol lewat `can()`; toast via `HX-Trigger` + daisyUI `toast`.
- Verifikasi: tanpa JS, form create/delete tetap jalan; dengan JS, tanpa reload.

**Phase 6 — OAuth2 authorize + PKCE (1.5 hari, opsional tapi disarankan)**
- `GET /oauth/authorize` + `POST /oauth/token` (`authorization_code`, `refresh_token`).
- Code sekali pakai, `redirect_uri` exact match, PKCE S256 wajib untuk kind `spa`.
- Verifikasi: test integrasi full flow.

**Phase 7 — Hardening + delivery (1–2 hari)**
- `middleware/audit.rs`: isi app_id/actor/action/path/status/request_id (action dari
  `RouteDef.audit_action`).
- Security header + CSP console; cookie `Secure` di prod.
- utoipa `/openapi.json` + `/docs` (required scope dari registry).
- Docker image multi-stage, CI: fmt + clippy -D warnings + `SQLX_OFFLINE=true cargo test`
  + `cargo deny`.
- README quickstart 5 baris.

Estimasi total: 8–10 hari kerja fokus.

---

## 11. Alur kerja dev: cargo watch + Makefile

```make
# Makefile
SHELL := /bin/bash
DB_URL ?= postgres://sanca:sanca@localhost:5433/sanca_dev
export DATABASE_URL := $(DB_URL)

.PHONY: help db db-down dev run build test fmt clippy migrate prepare docker docker-run clean

help:            ## daftar target
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

db:              ## postgres 18 saja (dev)
	docker compose up -d db
	@until docker compose exec -T db pg_isready -U sanca -d sanca_dev >/dev/null 2>&1; do sleep 0.5; done

db-down:
	docker compose down

dev:             ## auto-reload: src/, templates/, sql/, assets/
	cargo watch -w src -w templates -w migrations -w assets -x "run --bin sanca"

run:
	cargo run --bin sanca

build:
	cargo build --release

test:
	cargo test --all-features

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets -- -D warnings

migrate:
	sqlx migrate run

prepare:         ## refresh .sqlx cache (wajib setelah ubah query)
	cargo sqlx prepare -- --all-targets

docker:
	docker build -t sanca:local .

docker-run:
	docker compose --profile app up -d --build
```

Catatan:
- `cargo watch` me-restart proses tiap file di `src/`/`templates/` berubah. Karena askama
  compile-time, template berubah = recompile (itu memang yang diinginkan, jadi error
  template ketangkap saat build).
- Migrasi baru: `make migrate` lalu `make prepare`, commit `.sqlx/` dan file migrasi.
- **Tidak ada langkah build CSS.** `assets/vendor/daisyui.css` dan `htmx.min.js` adalah
  dependency yang di-vendor (di-commit), `assets/app.css` ditulis tangan. Tidak ada
  Node/Tailwind/purge di mesin dev maupun di Dockerfile.
- `rust-embed` default-nya membaca dari disk pada build **debug** (jadi ubah CSS/asset
  langsung kelihatan tanpa recompile), dan meng-*embed* ke binary pada build **release**.
- `cargo watch -x "run"` jangan dipakai bersama `docker compose up app` di terminal sama
  (port bentrok).

---

## 12. Docker: 2 stage, base kecil & stabil

Pilihan base runtime (semua diverifikasi ada di registry):

| Base | Ukuran | Catatan |
|---|---|---|
| `gcr.io/distroless/cc-debian12:nonroot` | ±24 MB | **pilihan default** — glibc, CA cert, non-root, tanpa shell (permukaan serang kecil) |
| `gcr.io/distroless/static-debian12:nonroot` | ±2 MB | butuh binary musl/static penuh; paling kecil |
| `debian:bookworm-slim` | ±75 MB | paling kompatibel, ada shell (debug) |
| `alpine:3.22` | ±8 MB | musl; aman karena sqlx+rustls tanpa OpenSSL, tapi glibc-vs-musl berisiko di crate tertentu |

**Rekomendasi:** builder `lukemathwalker/cargo-chef:latest-rust-1-slim-bookworm`
(build glibc) → runtime `distroless/cc-debian12:nonroot`. Stabil (glibc sama dengan
builder), kecil (24 MB), tanpa shell. Kalau butuh < 5 MB, switch ke musl static + 
`static-debian12:nonroot` — catat sebagai opsi, jangan default, karena seluruh crate harus
kompatibel musl.

```dockerfile
# syntax=docker/dockerfile:1.7
# ---------- stage 1: builder ----------
FROM lukemathwalker/cargo-chef:latest-rust-1-slim-bookworm AS chef
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
RUN cargo install sqlx-cli --no-default-features -F postgres,rustls --locked

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# cache dependency layer
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
# sqlx offline: tidak butuh DB saat build
ENV SQLX_OFFLINE=true
RUN cargo build --release --locked --bin sanca \
 && strip target/release/sanca

# ---------- stage 2: runtime ----------
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=builder /app/target/release/sanca /app/sanca
USER nonroot:nonroot
ENV IAM_BIND=0.0.0.0:8080 SANCA_ENV=prod
EXPOSE 8080
ENTRYPOINT ["/app/sanca"]
```

Stage 2 sengaja hanya menyalin **binary**: template (askama), asset (`rust-embed`), dan
migrasi (`sqlx::migrate!`) semuanya sudah ter-*embed* saat compile. Tidak ada file yang
harus ikut ke image, jadi tidak ada risiko "deploy lupa copy folder".

Catatan build:
- `.dockerignore`: `target/`, `.git/`, `.env`, `.sqlx` **jangan** diabaikan di
  builder kalau pakai `SQLX_OFFLINE=true` (cache harus ikut), hanya `/target` dan `.env`.
- Migrasi **tidak** dijalankan otomatis oleh image; jalankan `sanca migrate` (subcommand)
  atau `sqlx migrate run` di job terpisah. Container app harus bisa start tanpa DDL.
- Healthcheck compose pakai endpoint HTTP, bukan `pg_isready` di container app.

```yaml
# docker-compose.yml
services:
  db:
    image: postgres:18
    environment:
      POSTGRES_USER: sanca
      POSTGRES_PASSWORD: sanca
      POSTGRES_DB: sanca_dev
    ports: ["5433:5432"]
    volumes: ["sanca_pgdata:/var/lib/postgresql/data"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sanca -d sanca_dev"]
      interval: 2s
      retries: 30

  app:                      # profil: app (prod-like), tidak dipakai untuk dev harian
    profiles: ["app"]
    build: .
    env_file: [.env]
    environment:
      DATABASE_URL: postgres://sanca:sanca@db:5432/sanca_dev
      IAM_BIND: 0.0.0.0:8080
    ports: ["8080:8080"]
    depends_on:
      db: { condition: service_healthy }
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp"]
    healthcheck:
      test: ["CMD", "/app/sanca", "healthcheck"]   # subcommand internal, bukan curl
      interval: 10s

volumes:
  sanca_pgdata:
```

Alur harian: `make db` (postgres saja) + `make dev` (cargo watch di host) — cepat, hot
reload. Image Docker hanya diuji sebelum push/release (`make docker-run`).

---

## 13. Testing & verifikasi

| Level | Alat | Contoh target |
|---|---|---|
| DB integration | `#[sqlx::test]` (Postgres nyata) | `resolve_scope`, rotasi refresh, unique email |
| Auth unit | `cargo test` | argon2 verify, JWT aud mismatch, pepper version |
| Route registry | `cargo test` | setiap permission string di handler ada di ROUTES |
| HTTP E2E | `axum::Router` + `tower::ServiceExt::oneshot` | login → protected route → 200; tanpa scope → 403 |
| JWKS | E2E | bentuk JWK valid, rotasi key, kid palsu |
| Console | snapshot HTML fragment | nav menyembunyikan menu tanpa permission |

CI (`.github/workflows/ci.yml`): `fmt --check` → `clippy -D warnings` → `SQLX_OFFLINE=true
cargo test` → `cargo deny check` → `docker build`.

---

## 14. Keputusan yang masih terbuka

1. **Sanca menggantikan Mangosteen atau paralel?** Kalau paralel dan Granate/Salak/Kelapa
   sudah jalan, klaim JWT harus kompatibel (`sub`, `role`, `exp`). Sebutkan klaim wajib sama.

### Keputusan yang sudah diambil (24 Okt 2026)

Sisanya di atas (item 1) masih benar-benar terbuka: itu keputusan produk, bukan teknis.

2. **Email case-insensitive → `citext`.** Diverifikasi nyata di image `postgres:18`
   (18.6): `pg_available_extensions` memuat `citext 1.8`. Dipilih karena query tetap
   `WHERE email = $1` tanpa `lower()` di setiap tempat — satu kelas bug hilang.
   Kalau suatu saat pindah ke DB managed yang melarang extension, migrasi 0003 wajib:
   `ALTER TABLE users ALTER COLUMN email TYPE text`, lalu unique index `lower(email)`.

   **Jebakan wajib diingat (diuji, bukan teori):** bind parameter Rust bertipe `text`,
   jadi `WHERE email = $1` membandingkan `citext` dengan `text` secara case-SENSITIVE —
   tes langsung di psql: parameter tanpa cast menghasilkan 0 baris, dengan `$1::citext`
   menghasilkan 1 baris. Setiap query yang membandingkan kolom `citext` wajib menulis
   cast eksplisit `= $n::citext`. Ini berlaku untuk `users.email` dan apa pun yang
   memakai tipe itu nanti.

3. **Instant revocation → hanya di endpoint sensitif.** Cek `users.token_version` dilakukan
   di mutasi role/permission, logout-all, ganti password, dan rotate secret. Tidak ada
   query DB per request, tidak ada Redis di MVP. Konsekuensi yang diterima: token yang
   sudah terbit tetap hidup sampai `exp` (≤15 menit) di route biasa.

4. **Console terikat app `core`.** Tidak ada app switcher. App lain memakai API.
   Konsekuensi: `permissions`/`roles` milik app lain tidak tampil di console core,
   dan itu disengaja sampai ada kebutuhan nyata.

5. **`audit_events` tidak dipartisi** di MVP. Ambang tinjauan ulang: > 1k request/menit
   atau tabel melewati ~50 juta baris.

6. **Log aplikasi → stdout saja (JSON di prod).** Tidak ada file log, tidak ada
   `SANCA_LOG_DIR`, tidak ada `tracing-appender`. Alasan: nol kode rotasi, nol path yang
   bisa hilang, dan container sudah menangkap stdout. Konsekuensi infra: Alloy tidak boleh
   lagi men-tail `/var/log/sanca/*.log`; dia harus membaca log container
   (`loki.source.docker` + mount `/var/run/docker.sock`) dan label `env` diisi per-deploy.
   Volume `sanca_logs` dan env `SANCA_LOG_DIR` di `docker-compose.yml` jadi usang dan
   dihapus saat Alloy disetel ulang.

7. **Rotasi signing key → `SANCA_KEY_DIR`.** Satu file PEM per `kid` (0600), DB hanya
   menyimpan public key + status. `JWT_PRIVATE_KEY_PEM`/`JWT_PRIVATE_KEY_PATH` tetap ada
   sebagai jalur bootstrap dev, tapi bukan mekanisme rotasi. Tidak ada private key di DB
   pada MVP ini; kalau nanti butuh multi-instance tanpa file share, opsi `SANCA_MASTER_KEY`
   (envelope XChaCha20-Poly1305) dibuka lagi sebagai ADR baru.
