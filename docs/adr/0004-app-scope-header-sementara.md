# ADR 0004 — Header `X-Sanca-App` sementara di route terautentikasi

Status: diterima sementara, wajib dicabut di Phase 4
Tanggal: 2026-10-25

## Konteks

Phase 2B memasang ekstraktor autentikasi (`AuthUser`, `AuthApp`). Saat itu belum ada
registry `ROUTES` yang memetakan route ke app pemiliknya — registry baru datang di
Phase 4. Tanpa pemetaan itu, ekstraktor tidak punya nilai `expected_aud` untuk
memverifikasi token.

## Keputusan

Ekstraktor membaca slug app dari header `X-Sanca-App`, mencari app aktif dengan slug
itu, lalu memverifikasi token dengan `aud` = slug tersebut.

Ini **bukan** sumber otorisasi: slug bukan rahasia, dan token milik app lain tetap
ditolak 401 karena tanda tangan diverifikasi terhadap `aud` yang diminta. Yang bisa
dilakukan penyerang hanyalah menyebabkan 401 pada request-nya sendiri.

## Konsekuensi

- Klien wajib mengirim dua header (`Authorization` + `X-Sanca-App`). Klien yang tokennya
  valid tetap bisa mendapat 401 hanya karena salah menyebut slug.
- Setiap endpoint baru yang memakai ekstraktor sebelum Phase 4 mewarisi kontrak ini.
- Slug app efektif diduplikasi: sudah ada di klaim `aud`, tapi klien harus menyebutnya lagi.

## Rencana pencabutan (Phase 4)

Registry `ROUTES` (`RouteDef` per `MatchedPath`) menentukan app pemilik route. Ekstraktor
mengambil `expected_aud` dari registry, bukan dari header. Setelah itu header
`X-Sanca-App` dihapus dari ekstraktor dan dari test, dan perubahan itu breaking untuk
klien — catat di footer commit sebagai `BREAKING CHANGE`.
