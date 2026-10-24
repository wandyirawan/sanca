# ADR 0005 — Sanca berdiri sendiri, bukan pengganti Mangosteen

Status: diterima
Tanggal: 2026-10-25

## Konteks

AGENTS.md §14 butir 1 membiarkan pertanyaan terbuka: apakah Sanca menggantikan Mangosteen,
atau keduanya jalan paralel. Kalau paralel dan Mangosteen sudah dipakai app lain (Granate,
Salak, Kelapa), klaim JWT Sanca harus kompatibel (`sub`, `role`, `exp`) supaya service yang
sudah ada tidak perlu diubah. Kalau Sanca entitas terpisah, tidak ada kewajiban itu.

## Keputusan

Sanca adalah **entitas lain dan tidak menggantikan Mangosteen**. Keduanya boleh hidup
berdampingan, masing-masing untuk app yang berbeda. Tidak ada kewajiban kompatibilitas klaim
dengan Mangosteen.

## Konsekuensi

- Bentuk klaim token Sanca bebas mengikuti kebutuhan desainnya sendiri (AGENTS §6), termasuk
  `azp`, `sid`, `tv`, dan `scope` yang tidak ada di Mangosteen.
- Service yang mau memakai Sanca harus memakai verifier Sanca (JWKS di
  `/.well-known/jwks.json`), bukan verifier Mangosteen.
- Tidak ada migrasi data atau adaptor klaim. Tidak ada upaya menjaga `sub` identik antar dua
  sistem; pemetaan user antar sistem (kalau nanti dibutuhkan) adalah pekerjaan terpisah,
  bukan bagian dari Sanca.
- Nama app di Sanca (`core`, dan app lain yang dibuat lewat CLI) tidak harus sama dengan nama
  app di Mangosteen.
