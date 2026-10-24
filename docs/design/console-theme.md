# Spesifikasi visual & UX console Sanca

Dokumen ini mengikat pekerjaan Phase 5 (console HTMX + daisyUI). Sifatnya keputusan desain yang
sudah dihitung, bukan mood board: setiap pasangan warna di bawah punya angka kontras WCAG yang
bisa diperiksa ulang.

## 1. Arah rasa

Tiga kata: **tanah, tenang, presisi**. Sanca adalah ular tanah — penjaga gerbang yang tidak
mencari perhatian. Console bukan dashboard marketing: tidak ada gradien ungu, tidak ada glass
effect, tidak ada animasi yang memamerkan diri.

Yang diambil dari referensi: kerapatan tabel ala konsol enterprise (banyak data, sedikit hiasan),
tapi dengan disiplin ruang dan tipografi ala produk developer modern.

## 2. Pelajaran dari konsol IAM yang sudah ada

| Produk | Yang bekerja | Yang tidak boleh ditiru | Keputusan Sanca |
|---|---|---|---|
| Keycloak (admin console v2) | Cakupan fitur jelas, navigasi kiri konsisten | Form bertingkat, label teknis bocor ke UI ("client scope", "mapper"), dark mode lama hanya di halaman login (issue #26178), kepadatan tanpa hierarki | Label manusiawi, satu form satu tujuan, dark mode setara di semua halaman |
| Zitadel | Bersih, tabel rapi, default gelap yang enak | Mode console dan login bisa tidak sinkron (dilaporkan pengguna), Angular berat | Satu tema untuk login + console, diambil dari `data-theme` yang sama |
| Authentik | Tailwind, dark mode nyata, tata letak lega | Terlalu banyak panel pengaturan terbuka sekaligus | Detail disembunyikan di halaman detail, bukan di list |
| SuperTokens / Clerk / WorkOS | Empty state yang mengajari, inline docs, copy yang manusiawi, dark/light parity | Terkunci di SaaS | Empty state + mikro-copy diadopsi, tetap self-hosted |

Aturan turunan:

1. **Paritas tema wajib.** Setiap layar diuji di `tanah-malam` dan `tanah-siang`. Tidak ada
   "nanti dilengkapi" — tema yang tidak diuji = tema yang rusak.
2. **Halaman login memakai tema yang sama** dengan console. Tidak ada lompatan visual.
3. **Satu aksi primer per layar.** Sisanya sekunder atau tersembunyi di menu baris.
4. **Tidak ada istilah internal di UI.** `aud`/`azp`/`scope` muncul sebagai "Aplikasi"/
   "Izin"/"Akses", dan istilah teknis hanya di tooltip atau halaman detail.
5. **Empty state mengajari, bukan menghibur.** Contoh: "Belum ada aplikasi. Aplikasi adalah
   service yang memakai Sanca untuk login. Tambah aplikasi pertama." + tombol.

## 3. Palet "tanah"

daisyUI 5 memakai OKLCH sebagai ruang warna tema, jadi nilai di bawah ditulis sebagai OKLCH
(nilai hex hanya untuk pratinjau, bukan sumber kebenaran).

### `tanah-malam` (gelap)

```
[data-theme="tanah-malam"] {
  color-scheme: dark;
  --color-base-100: oklch(18.0% 0.012 60);   /* #16100c  latar utama, cokelat hampir hitam */
  --color-base-200: oklch(22.0% 0.014 60);   /* #201914  panel/kartu */
  --color-base-300: oklch(27.0% 0.016 60);   /* #2c251f  border & garis pemisah */
  --color-base-content: oklch(92.0% 0.015 75); /* #ebe3da  teks */
  --color-primary: oklch(62.0% 0.130 42);    /* #c66843  tanah liat/terakota */
  --color-primary-content: oklch(16.0% 0.020 45); /* #150a06 */
  --color-secondary: oklch(58.0% 0.090 135); /* #63864f  lumut */
  --color-secondary-content: oklch(15.0% 0.015 140); /* #080d07 */
  --color-accent: oklch(76.0% 0.140 78);     /* #e1a536  kunyit/amber */
  --color-accent-content: oklch(18.0% 0.020 80); /* #161107 */
  --color-neutral: oklch(30.0% 0.012 60);    /* #322c28 */
  --color-neutral-content: oklch(92.0% 0.012 75); /* #e9e4dc */
  --color-info: oklch(68.0% 0.100 235);      /* #54a2cd */
  --color-info-content: oklch(16.0% 0.020 235);
  --color-success: oklch(66.0% 0.120 145);   /* #60a563 */
  --color-success-content: oklch(15.0% 0.020 145);
  --color-warning: oklch(78.0% 0.130 80);    /* #e3ad4b */
  --color-warning-content: oklch(18.0% 0.020 80);
  --color-error: oklch(60.0% 0.170 25);      /* #d24c49  bata */
  --color-error-content: oklch(15.0% 0.020 25);
}
```

### `tanah-siang` (terang)

```
[data-theme="tanah-siang"] {
  color-scheme: light;
  --color-base-100: oklch(97.5% 0.012 85);   /* #faf6ee  kertas */
  --color-base-200: oklch(94.5% 0.016 85);   /* #f2ece1  panel */
  --color-base-300: oklch(89.5% 0.020 82);   /* #e3dbce  border */
  --color-base-content: oklch(25.0% 0.020 60); /* #291f18 */
  --color-primary: oklch(47.5% 0.120 40);    /* #924021  terakota tua (perlu lebih gelap agar AA) */
  --color-primary-content: oklch(98.5% 0.010 80); /* #fefaf3 */
  --color-secondary: oklch(44.0% 0.085 140); /* #385e2f */
  --color-secondary-content: oklch(98.5% 0.010 80);
  --color-accent: oklch(62.0% 0.130 75);     /* #b37903 */
  --color-accent-content: oklch(16.0% 0.020 75);
  --color-neutral: oklch(32.0% 0.014 60);    /* #38312c */
  --color-neutral-content: oklch(98.5% 0.010 80);
  --color-info: oklch(48.0% 0.110 240);      /* #006495 */
  --color-info-content: oklch(98.5% 0.010 80);
  --color-success: oklch(45.0% 0.110 150);   /* #196632 */
  --color-success-content: oklch(98.5% 0.010 80);
  --color-warning: oklch(70.0% 0.140 78);    /* #cd9219 */
  --color-warning-content: oklch(18.0% 0.020 78);
  --color-error: oklch(50.0% 0.170 25);      /* #b02a2d */
  --color-error-content: oklch(98.5% 0.010 80);
}
```

Bentuk: `--radius-box: 0.5rem`, `--radius-field: 0.375rem`, `--radius-selector: 0.25rem`,
`--border: 1px`, `--depth: 0`, `--noise: 0`. Sudut sedikit tegas, tanpa bayangan palsu —
konsol ini bukan situs marketing.

### Kontras terukur (rasio WCAG, dihitung dari OKLCH → sRGB)

| Pasangan | tanah-malam | tanah-siang |
|---|---|---|
| base-content / base-100 | 14.85 | 14.94 |
| base-content / base-200 | 13.68 | 13.67 |
| base-content / base-300 | 11.91 | 11.72 |
| primary-content / primary | 5.08 | 6.75 |
| secondary-content / secondary | 4.74 | 7.18 |
| accent-content / accent | 8.62 | 5.22 |
| info-content / info | 6.85 | 6.17 |
| success-content / success | 6.62 | 6.77 |
| warning-content / warning | 9.29 | 6.92 |
| error-content / error | 4.60 | 6.28 |
| primary / base-100 (teks link) | 4.91 | 6.56 |

Semua pasangan di atas ≥ 4.5:1 (AA teks normal). Ambang yang wajib dijaga saat tema diubah:
teks di atas `primary`/`error` adalah dua yang paling tipis, jangan digeser tanpa hitung ulang.

## 4. Tipografi

Modern-sci-fi yang tetap terbaca untuk tabel data — dua keluarga, tidak lebih:

| Peran | Font | Alasan |
|---|---|---|
| UI + heading | **Space Grotesk** (variable, 300–700) | bentuk geometris dengan detail teknikal, angka tabular, x-height besar → nyaman di tabel padat |
| Angka, ID, token, kode, `client_id` | **JetBrains Mono** (400/600) | token & UUID tidak boleh ambigu huruf/angka; `tabular-nums` |
| Nama halaman | Space Grotesk 600, `letter-spacing: -0.01em` | karakter "sci-fi tenang" di judul saja, bukan di badan |

Chakra Petch tersedia sebagai alternatif yang lebih agresif untuk judul, tapi **jangan** untuk
badan tabel — terlalu sempit dan membuat mata lelah dalam 5 menit.

Aturan: font di-vendor di `assets/vendor/fonts/*.woff2` (subset latin + latin-ext) dengan
`@font-face` dan `font-display: swap`. **Tanpa CDN.** Lisensi keduanya OFL 1.1 (boleh di-bundle,
atribusi disimpan di `assets/vendor/fonts/LICENSE-*.txt`).

Skala: `--text-xs 0.75rem` (label tabel), `--text-sm 0.875rem` (badan), `--text-base 1rem`,
`--text-lg 1.125rem` (judul kartu), `--text-2xl 1.5rem` (judul halaman). Line-height 1.45 badan,
1.25 judul.

## 5. Prinsip UX yang dipegang

1. **Tanpa reload penuh untuk aksi berulang.** Semua form dan filter memakai HTMX; halaman penuh
   hanya untuk navigasi.
2. **Search dulu, bukan paging buta.** Kotak cari dengan debounce 300 ms, hasil menggantikan
   `<tbody>`. Paging memakai cursor (bukan `OFFSET` besar).
3. **Aksi destruktif pakai konfirmasi bertuliskan nama objek** ("Hapus aplikasi *salak*"), dan
   tombolnya bukan tombol primer.
4. **Toast tidak mencuri fokus**, muncul `HX-Trigger` + `hx-swap-oob`, hilang setelah 5 detik,
   `aria-live="polite"`. Error validasi form ditampilkan **inline di field**, bukan toast.
5. **Setiap tabel punya empty state + empty-after-filter state** (beda kalimatnya).
6. **Keyboard-first:** `/` fokus ke pencarian, `g` + `u` → Users, `g` + `a` → Apps, `?` → daftar
   shortcut, `Esc` tutup modal. Tidak ada shortcut yang menimpa input teks.
7. **Fokus terlihat jelas** di kedua tema (`outline: 2px solid var(--color-primary)`,
   `outline-offset: 2px`) — jangan pernah `outline: none` tanpa pengganti.
8. **Tanpa JS, tetap jalan.** Form create/delete biasa (POST ke endpoint console) harus berfungsi
   dengan JS mati; HTMX adalah peningkatan, bukan syarat.
9. **Hormati `prefers-reduced-motion`.** Transisi maksimum 150 ms dan tidak wajib.
10. **Kepadatan bisa dipilih:** baris tabel `comfortable` (default) dan `compact` (untuk auditor
    yang memelototi log).

## 6. Peta komponen (daisyUI 5)

| Kebutuhan | Kelas |
|---|---|
| Shell | `drawer` + `navbar` + `menu` (sidebar kiri, kolaps di layar < 1024px) |
| Kartu statistik dashboard | `stats`, `stat` |
| Daftar entitas | `table table-zebra` + badge status |
| Form create/edit | `modal` + `fieldset` + `input`/`select` |
| Konfirmasi hapus | `modal` + `alert alert-warning` + tombol `btn-error btn-outline` |
| Notifikasi hasil | `toast toast-end` + `alert` |
| Filter/status | `filter` + `badge` (`badge-success`, `badge-warning`, `badge-ghost`) |
| Katalog permission | `join` + `checkbox` (matrix role × permission) |
| Pagination | `join` + `btn btn-sm` |
| Loading | `skeleton` (bukan spinner penuh layar) |

## 7. Screenshot & uji terima visual (Phase 5)

Wajib dibuktikan, bukan diklaim: setiap layar (login, dashboard, users, apps, RBAC matrix, audit)
diambil screenshot di kedua tema, dicek: kontras teks, fokus keyboard, empty state, dan lebar
1280px + 768px. Hasilnya ditempel di laporan Phase 5.

## 8. Yang sengaja tidak dilakukan

- Tidak ada gradient mewah, glassmorphism, animasi parallax, atau ilustrasi 3D.
- Tidak ada ikon yang tidak punya label di elemen penting (ikon tanpa teks hanya untuk aksi
  yang sudah jelas dan berulang, dan selalu punya `aria-label`).
- Tidak memakai CDN font/CSS: console harus jalan di jaringan tertutup.
- Tidak menambah build step (Tailwind tetap tidak dipakai — CSS daisyUI di-vendor).
