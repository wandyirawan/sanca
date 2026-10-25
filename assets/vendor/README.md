# Aset pihak ketiga yang di-vendor

Semua berkas di direktori ini di-commit apa adanya, bukan hasil build. Console harus
tetap jalan di jaringan tertutup, jadi tidak ada satu pun URL CDN di template.

| Berkas | Versi | Sumber | Ukuran mentah |
|---|---|---|---|
| `daisyui.css` | 5.7.50 | `https://cdn.jsdelivr.net/npm/daisyui@5.7.50/daisyui.css` | 1.142.434 byte |
| `htmx.min.js` | 2.0.11 | `https://cdn.jsdelivr.net/npm/htmx.org@2.0.11/dist/htmx.min.js` | 52.182 byte |
| `fonts/*.woff2` | — | Google Fonts CSS2 API (`fonts.gstatic.com`), subset latin + latin-ext | lihat tabel di bawah |

## Font

Diambil dari Google Fonts dengan User-Agent browser modern supaya yang dikirim adalah
woff2, bukan TTF. Hanya dua subset yang disimpan: `latin` dan `latin-ext`. Subset lain
(cyrillic, greek, vietnamese) sengaja dibuang karena console berbahasa Indonesia.

| Berkas | Keluarga | Berat | Subset |
|---|---|---|---|
| `space-grotesk-300-700-latin.woff2` | Space Grotesk (variable) | 300–700 | latin |
| `space-grotesk-300-700-latin-ext.woff2` | Space Grotesk (variable) | 300–700 | latin-ext |
| `jetbrains-mono-400-latin.woff2` | JetBrains Mono | 400 | latin |
| `jetbrains-mono-400-latin-ext.woff2` | JetBrains Mono | 400 | latin-ext |
| `jetbrains-mono-600-latin.woff2` | JetBrains Mono | 600 | latin |
| `jetbrains-mono-600-latin-ext.woff2` | JetBrains Mono | 600 | latin-ext |

Keduanya dilisensikan OFL 1.1; teks lisensi ada di `LICENSE-SpaceGrotesk.txt` dan
`LICENSE-JetBrainsMono.txt` (diambil dari repositori `google/fonts`).

Catatan pembaruan: kalau versi daisyUI naik, ganti berkasnya lalu perbarui angka di
tabel ini. Jangan menyalin CSS hasil build Tailwind — yang dipakai adalah berkas full
bawaan paket, sesuai keputusan di AGENTS.md §4.
