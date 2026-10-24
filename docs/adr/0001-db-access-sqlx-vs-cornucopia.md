# ADR 0001 — Akses DB: sqlx (macro) vs cornucopia (codegen ala sqlc)

Status: diterima, 2026-10-24
Konteks: Sanca (IAM Rust + PostgreSQL). Mangosteen (Go) memakai sqlc.

## Keputusan

Pakai **sqlx 0.9.0** dengan macro `query!`, `query_as!`, dan `query_file_as!`.
Tidak memakai ORM. Tidak memakai cornucopia sebagai jalur utama.

## Fakta yang mendasari (diverifikasi, bukan asumsi)

1. **cornucopia 1.0.1 memang padanan sqlc.** README-nya mencantumkan
   `sqlc (Go) - Generate type-safe code from SQL` sebagai prior art. Versi 1.0
   (rilis 2026-08) adalah hasil merge dari fork Clorinde.
2. **Mekanisme cornucopia:** query `.sql` diberi anotasi `--! nama_query`, di-*prepare*
   ke Postgres hidup, lalu di-generate menjadi **crate Rust terpisah** yang di-include
   sebagai path dependency. Bukan file `.rs` di dalam crate yang sama seperti sqlc di Go.
3. **Runtime cornucopia = tokio-postgres + deadpool-postgres**, bukan sqlx. Default tipe
   waktu-nya `chrono`, bukan `time` (bisa di-remap lewat `cornucopia.toml`).
4. **Batasan cornucopia:** array hanya satu dimensi; custom type enum/composite/domain
   didukung; crate hasil generate tidak bisa di-publish bersama parent-nya kecuali
   di-publish terpisah (path dependency tidak boleh dipublish).
5. **sqlx punya `query_file_as!`** — SQL panjang boleh ditaruh di file `.sql` dan
   di-*compile-check* juga. Jadi "SQL di file terpisah" bukan keunggulan eksklusif sqlc.
6. **sqlx punya `#[sqlx::test]`** (bikin database sementara per test) dan
   `sqlx::QueryBuilder` (query dinamis untuk filter opsional).

## Alasan memilih sqlx

1. **Satu stack, satu dependency tree.** sqlx menyediakan pool, migrasi (`sqlx-cli`),
   test harness (`#[sqlx::test]`), dan TLS. Dengan cornucopia, kita memakai
   tokio-postgres + deadpool untuk runtime, tapi tetap butuh tool migrasi terpisah di atas
   Postgres. Dua stack DB dalam satu binary = dua jalur error, dua konfigurasi TLS.
2. **Tidak ada artefak generated yang di-commit.** Diff PR hanya berisi kode yang ditulis
   manusia. Dengan cornucopia, perubahan schema menghasilkan diff besar di crate generated,
   dan wajib regenerate sebelum build hijau.
3. **Escape hatch untuk query dinamis.** Halaman audit dan daftar user punya filter
   opsional (app, actor, rentang waktu, pencarian). Dengan query statis, tiap kombinasi
   jadi `WHERE ($1 IS NULL OR ...)` yang menyulitkan planner Postgres. `QueryBuilder`
   memberi jalan tengah tanpa meninggalkan crate.
4. **Pengalaman membaca error.** Macro sqlx menempelkan error ke span Rust di file yang
   diedit (kolom salah, tipe mismatch). Cornucopia memberi error bagus juga, tapi di
   laporan generate, bukan di titik pemakaian.
5. **Sqlc-feel tetap bisa dicapai.** Konvensi: SQL panjang disimpan di `sql/queries/*.sql`
   dan dipakai lewat `query_file_as!`. Hasilnya: SQL tetap bisa di-review sebagai SQL di
   PR, tapi type checking terjadi saat build, tanpa toolchain tambahan.

## Biaya yang kita terima (jujur)

- Build butuh Postgres hidup **atau** cache `.sqlx/` (offline). Mitigasi: `make prepare`
  setelah mengubah query, cache di-commit, CI pakai `SQLX_OFFLINE=true`.
- Query masih berupa string — refactor nama kolom baru ketahuan saat build, bukan saat
  menulis.
- Proc-macro error kadang panjang/noisy.

## Kapan keputusan ini harus ditinjau ulang

Pindah ke cornucopia kalau salah satu benar-benar terjadi:

- Tim lebih produktif dengan SQL 100% terpisah di `.sql` dan review SQL murni.
- Muncul kebutuhan **crate query bersama** untuk beberapa binary/workspace (cornucopia
  unggul di sini karena hasil generate memang crate).
- Build tanpa DB sama sekali jadi syarat mutlak dan `make prepare` dianggap beban.
- Kebutuhan `time` crate di DB layer tidak bisa dikompromikan (cornucopia default chrono).

Estimasi biaya pindah: ±1 hari (setup generate + crate + ganti pool + port query + test).
Bukan keputusan yang mahal, jadi tidak perlu over-engineer sekarang.
