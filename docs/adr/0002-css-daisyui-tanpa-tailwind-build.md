# ADR 0002 — CSS console: daisyUI vendored, tanpa build Tailwind

Status: diterima, 2026-10-24
Konteks: console admin server-rendered (askama + HTMX), binary tunggal, image distroless.

## Keputusan

- `assets/vendor/daisyui.css` (daisyUI 5.7.50, full build) di-*vendor* dan di-commit.
- `assets/vendor/htmx.min.js` (2.0.11) di-*vendor* dan di-commit.
- `assets/app.css` ditulis tangan untuk layout/tweak yang tidak dicakup daisyUI.
- **Tidak ada Tailwind, tidak ada bundler, tidak ada langkah build CSS** — baik di mesin dev
  maupun di Dockerfile.
- Disajikan lewat `rust-embed` (embed saat build release) + `tower_http::CompressionLayer`
  (gzip/brotli).

## Angka yang jadi dasar (diukur, bukan dikira)

| Item | Ukuran |
|---|---|
| `daisyui@5` full CSS | 1.142.434 B raw (≈1,14 MB) |
| `daisyui@5` full CSS, gzip | ≈63 kB (dokumentasi resmi daisyUI: "63kB compressed") |
| Subset "choose parts" dari CDN | 13,2 kB (79% lebih kecil, tapi manual dan rawan drift) |
| `htmx.min.js` 2.0.11 | 52.182 B |
| Tailwind standalone `tailwindcss-linux-x64` v4.3.3 | **106,6 MB** |

## Alternatif yang ditolak

1. **Tailwind CLI di Dockerfile (purge).** Hasil CSS jauh lebih kecil (±10 kB), tapi
   menambah 106,6 MB tool di stage builder dan satu layer besar. Untuk console internal,
   ini menukar ~50 kB transfer (sekali, lalu di-cache browser) dengan 106 MB tool di
   toolchain. Rasio manfaat/biayanya buruk.
2. **Commit hasil build CSS (artefak di git).** Menghindari tool di image, tapi
   memindahkan beban ke manusia: tiap ubah gaya wajib `make css` lalu commit ulang. Langkah
   manual yang gampang terlupa = sumber drift antara `input.css` dan `app.css`.
3. **CDN `daisyui@5` + `@tailwindcss/browser@4`.** Nol file di repo, tapi butuh network ke
   pihak ketiga saat buka console, melanggar CSP ketat, dan menambah dependency runtime
   untuk alat internal. Ditolak.
4. **Subset "choose parts" (13,2 kB).** Paling kecil, tapi harus menambah file per
   komponen tiap kali template memakai komponen baru. Drift-nya senyap (komponen tidak
   bergaya sampai ada yang sadar). Tidak sepadan untuk 50 kB.

## Konsekuensi yang diterima

- One-time transfer ±63 kB gzip untuk daisyUI (lalu HTTP cache). Untuk console yang dipakai
  admin, ini tidak relevan secara performa.
- Binary bertambah ±1,2 MB (CSS di-embed). Masih di bawah 40 MB total.
- Tidak ada utility class Tailwind. Layout ditulis dengan CSS sendiri atau class daisyUI
  (`drawer`, `grid` dari CSS manual, `table`, `modal`, `navbar`, `menu`).
- Asset bersifat *vendored dependency*, bukan build artifact: memperbarui daisyUI/HTMX =
  ganti file + catat versinya di AGENTS.md.

## Kapan ditinjau ulang

- Console perlu dipakai lewat jaringan lambat / publik, dan 63 kB jadi signifikan.
- Muncul kebutuhan utility-first yang besar (banyak halaman custom).
  Jalur yang sudah ditimbang: Tailwind CLI **di stage builder saja** (bukan dev machines,
  bukan CI cache yang terpisah), artifak TIDAK di-commit, CSS di-embed saat `cargo build`.
