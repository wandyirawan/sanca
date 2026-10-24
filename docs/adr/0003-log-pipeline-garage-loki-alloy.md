# ADR 0003 — Log pipeline: file → Alloy → Loki, dengan Garage sebagai S3 backend

Status: usulan, 2026-10-24
Konteks: Sanca (IAM Rust). User ingin: log ditulis ke file, dibaca di Loki, dan Garage
(S3 self-hosted, single node) ikut dipasang di Docker.

## Tiga peran yang harus dipisah

Kekeliruan yang paling sering muncul: mengira Garage bisa dipakai sebagai "tempat nulis file
log". Garage adalah **object storage S3**, bukan filesystem. Tidak ada `>> app.log` ke Garage,
dan tidak ada `tail -f` di atasnya.

| Peran | Apa | Contoh |
|---|---|---|
| **Penulis log** | proses yang menulis log | Sanca (file dan/atau stdout) |
| **Pengirim** | agent yang membaca file dan push ke Loki | Grafana Alloy |
| **Penyimpan log** | Loki (chunk + index) | Loki single binary |
| **Backend objek** | tempat Loki menyimpan chunk + index | Garage (S3) atau filesystem lokal |

Garage **bukan** penulis dan **bukan** pembaca log. Garage adalah backend penyimpanan Loki.
Itu peran yang masuk akal untuknya, dan itu memang cara Loki bekerja
(`storage_config.aws.s3` + `s3forcepathstyle: true`).

## Arsitektur yang disarankan

```
Sanca ──(JSON lines)──► /var/log/sanca/sanca.log   (volume Docker)
                              │
                              ▼  tail (loki.source.file)
                        Grafana Alloy  ──(loki.write)──►  Loki  ──►  Grafana (query)
                                                            │
                                                            └── chunk+index ──► Garage (S3)
```

Semua di `docker-compose.yml` (profil `obs`): `garage`, `loki`, `alloy`, `grafana`.
Bisa juga tanpa Garage dulu — Loki `filesystem` storage untuk POC, Garage dipasang ketika
mau satu backend S3 dipakai bersama (backup Postgres, export audit, artefak).

## Format log: JSON lines, satu event per baris

Alasan memilih JSON, bukan logfmt atau plain text:

1. Loki punya parser `| json` bawaan — field langsung jadi filter/structured metadata:
   `{app="sanca"} | json | status > 499 | app_slug="salak"`. Dengan plain text, setiap field
   butuh `| regexp` buatan sendiri yang rapuh dan mahal saat query.
2. Satu format untuk dua tujuan: stdout di dev tetap enak dibaca (pakai format `pretty`,
   bukan JSON), JSON dipakai di prod dan di file. Kode log-nya sama, hanya layer formatter
   yang berbeda.
3. Field bertipe (angka, boolean) tetap bertipe di Loki; jangan di-*quote* kalau memang angka.
4. Ukuran wajar: ±250–400 B per event. Untuk IAM volume rendah (±100 rb event/hari = ±40 MB
   JSON/hari sebelum kompresi).

Contoh satu baris (tanpa newline di dalamnya):

```json
{"ts":"2026-10-24T14:31:02.114Z","level":"INFO","target":"sanca::api::users","msg":"user created","request_id":"01J9...","method":"POST","path":"/api/users","status":201,"latency_ms":12,"app_slug":"core","actor_type":"user","actor_id":"0192f...","session_id":"0192e...","action":"user.create","resource_id":"0192a..."}
```

Aturan format:
- **Jangan** multi-line / pretty-print di file prod. Satu event = satu baris; agent tail
  berbasis baris, dan multi-line memaksa multiline parser yang rapuh.
- Field wajib sesuai skema di AGENTS.md §9. Nama field `snake_case` dan stabil — jangan
  pernah rename tanpa migrasi query dashboard.
- Larangan: password, token, header Authorization/Cookie, client_secret, body login/token.
- `ts` pakai RFC3339 dengan milidetik, zona UTC.

## Penulisan file di sisi Sanca

`tracing-subscriber` bisa punya dua layer sekaligus: `fmt` ke stdout + `fmt` JSON ke file.

```rust
// src/telemetry.rs (ringkas)
let file_appender = tracing_appender::rolling::RollingFileAppender::new(
    tracing_appender::rolling::Rotation::DAILY, // tracing-appender 0.2.5
    log_dir,                                    // mis. /var/log/sanca
    "sanca.log",                                // hasil: sanca.log.2026-10-24
);
let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
// guard WAJIB disimpan sampai shutdown, kalau di-drop log terakhir hilang
```

Batasan yang harus disadari (bukan bug, memang begitu):
- `tracing-appender` merotasi file tapi **tidak menghapus** file lama. Retensi file = tugas
  logrotate / sidecar kecil / cron. Kalau tidak diurus, disk penuh pelan-pelan.
- Writer non-blocking punya buffer; saat shutdown, `guard` harus di-flush.
- Kalau Loki/agent mati, file tetap jadi buffer alami. Ini keuntungan file dibanding
  langsung push HTTP: tidak ada log yang hilang saat collector down.

Alternatif yang lebih sederhana (kalau tidak butuh durability lokal): jangan tulis file
sama sekali, Alloy membaca stdout container lewat `loki.source.docker`. Satu komponen lebih
sedikit, tapi log hilang kalau Loki down dan container restart. Untuk IAM, file-based
pilihan yang lebih aman — sesuai usulan user.

## Pengiriman: Alloy, bukan Promtail

**Promtail sudah EOL 2 Maret 2026** (dinyatakan resmi di dokumentasi Grafana Loki;
pengembangan dipindah ke Grafana Alloy). Jadi jangan mulai dengan Promtail.

Alloy, potongan konfigurasi inti:

```alloy
local.file_match "sanca" {
  path_targets = [{ __path__ = "/var/log/sanca/*.log", app = "sanca", env = "prod" }]
}

loki.source.file "sanca" {
  targets    = local.file_match.sanca.targets
  forward_to = [loki.write.default.receiver]
}

loki.write "default" {
  endpoint { url = "http://loki:3100/loki/api/v1/push" }
}
```

Yang penting: `__path__` harus ikut pola file hasil rotasi (`*.log*`), karena nama file
berubah tiap hari. Kalau salah, log hari kemarin tidak pernah terbaca.

## Loki + Garage

Loki single binary, storage S3 menunjuk ke Garage (config shape untuk on-prem S3 sesuai
dokumentasi Loki: `s3: http://user:pass@host:port` + `s3forcepathstyle: true`):

```yaml
# loki-config.yaml (potongan)
schema_config:
  configs:
    - from: 2026-01-01
      store: tsdb
      object_store: s3
      schema: v13
      index: { prefix: loki_index_, period: 24h }

storage_config:
  aws:
    s3: http://ACCESS_KEY:SECRET_KEY@garage:3900
    s3forcepathstyle: true
    bucketnames: sanca-loki
  tsdb_shipper:
    active_index_directory: /loki/tsdb-index
    cache_location: /loki/tsdb-cache

limits_config:
  retention_period: 720h        # 30 hari

compactor:
  working_directory: /loki/compactor
  retention_enabled: true
  delete_request_store: s3
```

Garage single node (command resmi, gambar `dxflrs/garage:v2.4.1`): jalankan dengan
`garage server --single-node --default-bucket` — flag `--single-node` mengonfigurasi klaster
satu node tanpa replikasi otomatis (tidak perlu `layout assign` manual), `--default-bucket`
membuat access key + bucket dari env `GARAGE_DEFAULT_ACCESS_KEY`,
`GARAGE_DEFAULT_SECRET_KEY`, `GARAGE_DEFAULT_BUCKET`.

Port Garage: 3900 S3 API, 3901 RPC, 3902 web, 3903 admin/metrics.
Config default dibaca dari `/etc/garage.toml`, `replication_factor = 1`, `db_engine = sqlite`.
Data **hilang** kalau volume `data_dir`/`metadata_dir` tidak di-mount — pastikan volumenya ada.

Catatan penting soal Garage single node:
- `replication_factor = 1` → tidak ada redundansi. Kalau disk mati, log hilang. Untuk log
  diagnostik itu dapat diterima; untuk audit **jangan** (audit tetap di Postgres).
- Butuh bucket dibuat lebih dulu (Alloy/Loki tidak membuatnya); pakai `garage bucket create`
  atau `--default-bucket`.
- Garage ini juga cocok untuk hal lain nanti: backup dump Postgres, export audit_events
  (JSONL/Parquet), artefak build — bukan hanya Loki.

## Jangan lakukan ini

1. **Mount Garage lewat s3fs/goofs lalu menulis file log ke sana.** S3 tidak mendukung
   append; setiap penambahan baris berarti menulis ulang objek. Hasilnya lambat, mahal, dan
   file bisa korup. Ini kesalahan yang paling sering terjadi saat orang membayangkan S3
   sebagai disk.
2. **Menulis log langsung ke Garage via S3 PUT dari aplikasi.** Bisa (sink S3 ada di banyak
   logger), tapi Loki tidak bisa membaca objek S3 lewat jalur itu — Loki butuh chunk format
   internal. Hasilnya: dua sistem penyimpanan log yang tidak nyambung, dan tidak bisa di-tail.
3. **Memakai Promtail** (EOL), atau `loki.source.docker` untuk container yang menulis file
   sendiri (dobel: file + stdout).
4. **Log multi-line** (stack trace mentah, JSON pretty). Kalau butuh stack trace, jadikan
   satu field string yang di-*escape* di dalam satu baris JSON.
5. **Menyimpan log sebagai satu-satunya bukti audit.** Audit tetap di tabel `audit_events`.

## Biaya / sumber daya (perkiraan, single node)

| Komponen | RAM | Disk |
|---|---|---|
| Garage | ~100–200 MB | 1 GB+ (chunk Loki, kompresi) |
| Loki (single) | ~200–300 MB | index kecil (tsdb di Garage) |
| Alloy | ~50–80 MB | – |
| Grafana | ~150–250 MB | – |

Total ±0,6–0,8 GB RAM di host dev. Volume log 40 MB/hari JSON → ±1,2 GB/bulan sebelum
kompresi; Loki kompresi chunk ±5–10×, jadi di Garage realistis ±150–250 MB/bulan untuk 30
hari retensi.

## Retensi 90 hari: siapa yang sebenarnya menghapus?

**Yang menghapus log itu Compactor Loki, bukan storage backend.** Ini poin yang sering
keliru: orang mengira "di S3 lebih gampang dihapus" karena bisa pakai lifecycle policy.
Fakta dari dokumentasi Loki (retention):

- Retensi dicapai lewat **Compactor**; default `retention-enabled` mati, jadi log hidup
  selamanya kalau tidak diaktifkan.
- `compactor.delete_request_store` **wajib** diisi saat retensi aktif (`filesystem` atau `s3`,
  mengikuti backend).
- Retensi hanya tersedia kalau **index period 24h** (single store TSDB).
- Chunk tidak dihapus saat index diproses; ada **sweeper** terpisah dengan jeda
  `retention_delete_delay` supaya index gateway sempat menarik index baru.
- Perubahan periode retensi **tidak retroaktif**.
- Kalau ada **lifecycle policy di object store, periodenya harus LEBIH PANJANG dari
  retensi**. Kalau lebih pendek: chunk terhapus duluan sementara index masih menunjuk ke
  sana → query error "chunk not found". Lifecycle hanya backstop, bukan mekanisme retensi.

Konfigurasi 90 hari (2160 jam):

```yaml
limits_config:
  retention_period: 2160h        # 90 hari

compactor:
  working_directory: /loki/compactor      # butuh volume persistent (marker file)
  retention_enabled: true
  retention_delete_delay: 2h
  compaction_interval: 10m
  apply_retention_interval: 30m
  delete_request_store: s3                # atau `filesystem`
  retention_delete_worker_count: 50
```

Marker file default di `<working_directory>/retention/...`; kalau tidak mau bergantung
volume, set `deletion_marker_object_store_prefix` supaya marker disimpan di object store.

## S3/Garage vs filesystem untuk retensi

| | `filesystem` | S3 (Garage) |
|---|---|---|
| Mekanisme hapus | Compactor `unlink` file | Compactor `DELETE` objek (metadata + jaringan) |
| Ruang disk kembali | saat itu juga | setelah blok dibersihkan proses internal Garage — perlu headroom |
| Biaya operasi hapus | nol | nol (lokal), tapi tiap DELETE = operasi ke Garage |
| Jumlah service | 1 (Loki) | 2 (Loki + Garage) |
| Backup | `rsync`/snapshot direktori | `garage` CLI / S3 copy |
| Pindah backend nanti | tidak bisa; chunk lama tertinggal | portabel, S3 standar |
| Hemat uang di mesin sendiri | sama | sama |
| Mode deployment | single binary | bisa microservices/scalable |

**Kesimpulan untuk 90 hari:** "lebih mudah/murah dihapus" bukan pembeda — dua-duanya
dihapus komponen yang sama. Pembeda nyata: (a) reclaim ruang instan vs perlu GC internal,
(b) portabilitas backend, (c) jumlah proses yang dirawat.

Volume 90 hari: 35 MB/hari raw → **3,15 GB raw**, ±0,3–0,6 GB setelah kompresi chunk +
index kecil. Disk 20 GB sudah lega (±1 tahun).

Soal "fisik file-nya ada": yang benar-benar file log yang bisa `grep`/`tail` adalah
`/var/log/sanca/sanca.log` yang ditulis aplikasi — itu ada di kedua skenario dan itu yang
paling berguna saat insiden. Chunk Loki (filesystem maupun `data_dir` Garage) adalah blok
terkompresi, bukan teks yang bisa dibaca langsung.

## Biaya uang (angka terverifikasi)

Harga S3 us-east-1 per Okt 2026: Standard $0.023/GB-bulan, Standard-IA $0.0125,
Glacier IR $0.004; PUT/COPY/POST/LIST $0.005/1.000; GET $0.0004/1.000; egress $0.09/GB
setelah 100 GB gratis.

Untuk Sanca (100 rb event/hari × 350 B, kompresi 6×, retensi 90 hari): tersimpan ±0,5 GB →
**±$0.011/bulan** di S3 Standard (≈ Rp 180). Naik 10× volume jadi ±$0.076/bulan.

Biaya storage bukan faktor penentu di skala ini. Yang mahal: RAM host, operator time, dan
(kalau cloud) egress + request. Perbandingan yang benar: S3 self-hosted vs filesystem =
sama-sama Rp 0 tambahan; S3 Standard cloud masih ±3,5× lebih murah dari block storage
cloud (EBS gp3 ±$0.08/GB-bulan), dan jauh lebih murah dari log SaaS (±$0.5/GB ingested).

## Keputusan

- Format: **JSON lines**, satu event per baris, skema field AGENTS.md §9.
- Sanca menulis **stdout JSON** (wajib) + **file opsional** (`SANCA_LOG_DIR`, default kosong
  = file sink mati). Kalau `SANCA_LOG_DIR` diisi, aktifkan rolling harian + non-blocking.
- Pengirim: **Grafana Alloy** (bukan Promtail).
- Penyimpan: **Loki single binary**, backend **Garage** (S3) di profil compose `obs`.
- Retensi: **90 hari** (`limits_config.retention_period: 2160h`) lewat Compactor, berlaku di
  kedua opsi backend. Kalau lifecycle policy dipakai di bucket Garage, set **120 hari**
  sebagai backstop (harus > retensi, jangan sama).
- Retensi file lokal milik Sanca: logrotate/sidecar `maxsize` (mis. 14 hari atau 2 GB),
  karena `tracing-appender` tidak pernah menghapus file lama.

## Terbuka

1. Garage dipakai sejak hari pertama, atau Loki `filesystem` dulu lalu migrasi ke Garage?
   (Loki tidak bisa ganti backend tanpa menulis ulang chunk lama — sekali pilih, komit.)
2. File log ditaruh di volume Docker atau bind-mount ke host? Bind-mount lebih enak di-debug
   (`tail -f /var/log/sanca`), volume lebih bersih.
3. Perlu Grafana di compose yang sama, atau pakai Grafana yang sudah ada di mesin?
