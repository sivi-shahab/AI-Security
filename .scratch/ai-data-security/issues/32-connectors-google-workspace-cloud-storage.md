# 32: Connectors Google Workspace & cloud storage

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 31
Spec: `../spec.md` §4.3; §11

## Konteks
Memperluas coverage data-at-rest.

## Scope
- Connector Google Drive (changes API) + audit OAuth grant aplikasi AI.
- Connector S3/GCS/Azure Blob (event notification).
- Connector Compliance API ChatGPT Enterprise / Claude Enterprise bila dipakai bank.

## Acceptance criteria
- [x] Contract test per connector memakai SDK dari tiket 31. *(`internal/connector/connectortest`: satu suite untuk semua konektor, mencakup container ada, bootstrap ber-paging dengan content tag (dan ukuran bila dilaporkan), `Get` dan batas ukurannya, tanpa perubahan = tanpa item, perubahan konten dan penghapusan muncul di feed dan tidak ada yang lain, ACL/label/remediasi, serta sharing anonim terlihat di ACL (dan di feed bila sumbernya melaporkannya). Mode append-only untuk log dan mode turunan untuk transkrip. Dijalankan untuk M365 (Graph palsu), Google Drive (Drive/Directory/Reports palsu), S3 (**MinIO sungguhan**), GCS (MinIO via XML interop + format notifikasi Pub/Sub), Azure Blob (**emulator Azurite** dengan SAS asli), Claude Enterprise, dan ChatGPT Enterprise (server palsu mengikuti dokumentasi).)*

## Keputusan
- Scope sesuai pilihan: keempat jenis konektor dikerjakan. Semua mengimplementasikan `connector.Connector` sehingga scanner tiket 31 (inkremental, sampling, oversharing, exposure) berlaku tanpa perubahan. Retry/backoff diangkat menjadi `connector.Backoff` (Retry-After, eksponensial, batas tunggu dan retry) dan dipakai semua konektor HTTP, termasuk M365 yang di-refactor tanpa mengubah perilaku.
- **Google Drive** (`internal/connector/gdrive`): service account dengan domain-wide delegation, scope read-only (drive, directory user, reports audit). Container = setiap shared drive (sebagai admin pemindai) + My Drive setiap user aktif (impersonasi user itu; file milik orang lain dilewati karena dilaporkan oleh drive pemiliknya). Start token changes diambil sebelum listing, jadi tidak ada perubahan yang hilang selama bootstrap; sesudahnya changes API. Content tag = MD5 untuk file biner, `modifiedTime` untuk dokumen Google (berubah karena edit, bukan sharing). Dokumen/Sheets/Slides diekspor sebagai text/plain dan text/csv. Permissions: `anyone` = link anonim, domain bank = org, domain lain/eksternal = eksternal. Kuota Google (429 atau 403 `rateLimitExceeded`) di-backoff. Label Drive belum dibaca karena ID label per tenant perlu dikonfigurasi.
- **Audit OAuth grant** (`datascan.OAuthAudit`): Admin SDK Reports (token/authorize) → `data.oauth_grants` (app, scope gabungan, AI atau bukan) dan `data.oauth_grant_users` (email di-HMAC). Aplikasi AI dikenali dari kata kunci (ChatGPT, Claude, Gemini, Copilot, dll.) atau nama aplikasi di katalog AI (tiket 16; bukan vendor, agar "Google Drive for desktop" tidak terhitung). Aplikasi AI masuk antrean shadow agent tiket 27 (`agents.discovered`, sumber `oauth_grant`, id `oauth:<client_id>`). Laporan Google terlambat, jadi setiap pass membaca ulang 24 jam terakhir; pencatatannya idempoten.
- **Object storage** (`internal/connector/objstore`): satu konektor dengan dua backend, S3-compatible (minio-go: MinIO on-prem per ADR-0001, AWS S3, GCS lewat XML API dengan HMAC) dan Azure Blob (REST + account SAS list/read, tanpa SDK baru). Bucket = container. Pass pertama me-listing (id event terbaru dicatat lebih dulu), lalu feed = antrean notifikasi di Postgres (`data.object_events`) yang diisi `Receiver` di worker: `POST /events/{s3|gcs|azure}` dengan token (header atau query), untuk format S3/MinIO Records, GCS Pub/Sub push, dan Azure Event Grid (termasuk handshake validasi). Detail yang dites:
  - key S3 di event ter-URL-encode (diverifikasi dengan **payload webhook MinIO asli**: `laporan q3/a b+c.txt`);
  - md5Hash GCS (base64) dikonversi ke hex agar sama dengan ETag listing XML;
  - DELETE GCS milik generasi yang tertimpa diabaikan.

  ACL: bucket policy yang mengizinkan Principal `*` membaca (S3/MinIO) atau container dengan public access `blob`/`container` (Azure) dianggap link anonim. ACL per objek dan IAM `allUsers` GCS belum terlihat. Event lebih tua dari 7 hari dibuang.
- **Compliance API** (`internal/connector/compliance`), hanya dari bagian yang terverifikasi di dokumentasi resmi (riset 2026-10-04):
  - **Claude Enterprise**: Compliance Access Key (`x-api-key`, `anthropic-version`). Chat inkremental dengan `order_by=updated_at&updated_at.gt` + `after_id`; chat terhapus via `deleted_at`. Konten = transkrip pesan + teks file unggahan (file biner hanya disebut namanya). Throttling 429/529 dengan `retry-after`.
  - **ChatGPT Enterprise**: hanya **Compliance Logs** (`/workspaces/{id}/logs?event_type=conversation_message&after=` dengan `last_end_time`, unduhan JSONL) yang terverifikasi, karena referensi endpoint percakapan/file OpenAI terblokir (403) saat riset. Konektor membaca file log (append-only) dan mengklasifikasi seluruh isinya.
- `connector-worker` kini multi-sumber berbasis env (setiap sumber aktif bila variabelnya ada) dan menjalankan audit OAuth serta receiver event; Service ditambahkan untuk endpoint event. CI menambah service Azurite.

## Hasil verifikasi lokal (2026-10-04)
- `go test -race ./...` hijau dengan Postgres, MinIO, dan Azurite; uji webhook MinIO asli lolos; golangci-lint 0 issue; image `connector-worker` ter-build. Belum diuji terhadap Google Workspace, AWS, GCS, Azure, atau API vendor AI sungguhan (perlu kredensial bank).

## Sisa / follow-up
- ChatGPT Enterprise: endpoint percakapan/file dan field log yang lebih rinci perlu diverifikasi dari referensi Admin API OpenAI (sesi browser admin Enterprise / ekspor OpenAPI).
- Claude: file biner unggahan (docx/pdf) belum diekstrak; sharing hanya terlihat di Activity Feed (`claude_chat_snapshot_*`), belum dibaca.
- Label Google Drive; ACL per objek S3/GCS dan IAM `allUsers` GCS; notifikasi S3 dari AWS lewat SNS (format raw delivery sudah didukung, handshake konfirmasi SNS belum).
- Notifikasi bucket yang hilang (endpoint mati > 7 hari) memerlukan rescan (`cursor` dikosongkan).
- Grant OAuth dari Entra ID (consent aplikasi Microsoft 365) belum dibaca; tipe `connector.OAuthGrant` sudah generik.