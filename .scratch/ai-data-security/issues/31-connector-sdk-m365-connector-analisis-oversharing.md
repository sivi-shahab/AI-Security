# 31: Connector SDK + M365 connector + analisis oversharing

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 06, 08, 15
Spec: `../spec.md` §4.3 FR-DATA-1..5; §4.4 FR-CLS-5, FR-CLS-6; §11

## Konteks
Posture data-at-rest yang dikonsumsi Copilot/RAG.

## Scope
- Kontrak Connector SDK (`list_containers`, `list_items`, `get_item`, `get_acl`, `apply_remediation`) + checkpoint cursor.
- M365 connector (SharePoint/OneDrive/Teams) dengan delta query + baca label Purview.
- File extraction service tersandbox (Tika) dengan batas zip bomb.
- Sampling adaptif + analisis ACL: link anonim, share eksternal, grup luas, izin yatim.
- Output `DATA_ASSET`, `CLASSIFICATION_RESULT`, `exposure_score` tanpa raw content.

## Acceptance criteria
- [x] Scan incremental tidak mengulang item yang tidak berubah. *(`datascan.TestScan` (Postgres + Graph palsu): run kedua tanpa perubahan memproses 0 item dan tidak membaca konten maupun ACL. Setelah satu perubahan konten, satu perubahan sharing, dan satu penghapusan, tepat tiga item disentuh: konten hanya dibaca ulang untuk item yang cTag-nya berubah, item yang hanya berubah sharing-nya dibaca ACL-nya saja. Saat bootstrap, setiap file dibaca tepat sekali walau container beralih dari sampel ke full. Uji mutasi (cTag diabaikan) membuat test gagal.)*
- [x] Fuzz test parser file. *(`extract.FuzzExtract`: 90 detik, ±1,19 juta eksekusi, bersih; teks tidak pernah melewati batas. Unit test: zip bomb (20 MB nol), kedalaman 4, jumlah entri, ukuran input, batas teks.)*
- [x] Rate limit Graph API dihormati (backoff). *(`m365.TestThrottling`: 429 dengan `Retry-After: 7` → menunggu 7 s dua kali lalu sukses dengan satu fetch; 503 tanpa Retry-After → 1/2/4 s eksponensial; tunggu dibatasi `MaxBackoff`; setelah `MaxRetries` → `StatusError{Throttled}` yang tidak pernah dianggap "tanpa label". `TestScan` melewati 429 di tengah scan.)*

## Keputusan
- **Connector SDK** (`internal/connector`): `Containers`, `Items(container, cursor)`, `Get`, `ACL`, `Labels`, `Remediate`, yang memetakan `list_containers`, `list_items(cursor, since)`, `get_item`, `get_acl`, `apply_remediation`. Ditambah `Labels` untuk FR-CLS-6. Connector stateless; cursor dan checkpoint ada di Postgres (`data.containers`), disimpan setiap halaman.
- **M365** (`internal/connector/m365`): client credentials Entra (read-only: Sites.Read.All, Files.Read.All, User.Read.All). Container = setiap document library dari semua site (SharePoint dan Teams) plus OneDrive tiap user. Delta query per drive dengan `Prefer: deltashowsharingchanges, hierarchicalsharing`, sehingga perubahan sharing muncul di feed dengan cTag yang sama. Permissions dipetakan ke grant: link `anonymous`/`organization`/`users`, user (eksternal = guest `#EXT#` atau domain di luar `M365_DOMAINS`), dan grup. Label Purview lewat `extractSensitivityLabels`. Link `nextLink`/`deltaLink` hanya diikuti bila tetap di host Graph. Unduhan konten mengikuti redirect pre-authenticated tanpa membawa token.
- **Ekstraksi** (`internal/extract`, sesuai pilihan "Go native + Tika opsional"): teks, CSV, HTML/XML (script/style dibuang, komentar dipertahankan karena tempat injection bersembunyi), docx/xlsx/pptx (hanya part berisi konten), dan zip bersarang ditangani di Go, di memori, tanpa disk. Batas §13: 50 MB, kedalaman 3, rasio dekompresi 100× dari ukuran yang benar-benar terbaca (bukan header), 10.000 entri, teks 2 MB untuk klasifikasi. PDF, OLE2 (.doc/.xls), dan RTF lewat Tika server (dites dengan image `apache/tika:3.2.3.0` sungguhan); tanpa `TIKA_URL`, item seperti itu dinilai dari label dan ACL saja. Tika di-rebuild dan ditandatangani CI (`build/tika.Dockerfile`, digest di-pin), jalan di gVisor tanpa egress (NetworkPolicy), dan hanya worker yang bisa mengaksesnya. Worker sendiri juga di gVisor karena ikut mem-parse file.
- **Inkremental**: konten dibaca hanya bila item baru, cTag berubah, atau belum pernah diklasifikasi padahal kini terpilih. Item yang muncul di feed hanya karena sharing atau nama dibaca ACL-nya saja. Label dibaca ulang hanya saat konten berubah.
- **Sampling adaptif** (FR-DATA-3): setiap file tetap dicatat dengan ACL dan label; konten hanya dibaca untuk sampel deterministik 5% (hash id, stabil antar run, maks 10.000). Setelah pass bootstrap, container beralih ke `full` bila kecil (< 1.000 file) atau padat (≥ 5% sensitif dari ≥ 20 sampel), lalu dijalani ulang sekali untuk membaca yang terlewat (tanpa membaca ulang ACL atau konten yang sudah ada). Item yang tidak tersampel tercatat dengan `scan_note = 'not sampled'`.
- **Oversharing** (FR-DATA-4): `anyone_link`; `external_share`; `broad_group` (Everyone/All company/Semua karyawan, dan seterusnya) pada konten confidential atau restricted; `orphan_permission` (user non-aktif di direktori SCIM tiket 06; user yang tidak dikenal direktori tidak dianggap yatim).
- **Sensitivity** = level tertinggi dari detektor L1 dan label eksternal (label jadi batas bawah; peta label → sensitivity dari `M365_LABELS`). **Exposure score** 0–100 = 100 × sensitivitas (0/.3/.6/1) × jangkauan (anyone 1, eksternal .8, grup luas .6, yatim .3, privat .1).
- **Output** (FR-DATA-5): `data.assets` (external_id, HMAC path, cTag, label, sensitivity, exposure, flags, catatan scan), `data.classifications` (kelas, jumlah, confidence, versi model), `data.acl_entries` (grantee disimpan untuk remediasi tiket 33). Tidak ada konten mentah maupun path; test memeriksa seluruh baris di semua tabel. File yang gagal diekstrak (zip bomb, format tak didukung) diberi catatan dan tidak diambil ulang sampai versinya berubah.
- **API** (control-plane, `dashboard.read`): `GET /data/assets?min_exposure=&flag=&sensitivity=&source=&limit=` (urut exposure, termasuk kelas dan ACL) dan `GET /data/summary` (per sumber: jumlah, terklasifikasi, per sensitivity, per flag, exposure ≥ 60).
- Service baru `connector-worker` (interval `SCAN_INTERVAL`, default 1 jam). Replika berbagi kerja lewat advisory lock per container.

## Hasil verifikasi lokal (2026-10-04)
- `go test -race ./...` termasuk integrasi Postgres hijau; fuzz 90 detik bersih; ekstraksi PDF lewat Tika asli; golangci-lint 0 issue; image `connector-worker` dan `control-plane` ter-build. Belum diuji terhadap tenant M365 sungguhan (perlu app registration bank).

## Sisa / follow-up
- Flag "item sensitif yang terindeks Copilot/RAG": Graph tidak memberi status indeks per item. Perlu Restricted Content Discovery/Restricted SharePoint Search per site, atau log interaksi Copilot (§11).
- Rescan terjadwal penuh (mis. bulanan) untuk menyegarkan ACL yang di-inherit tanpa muncul di feed; densitas yang berubah setelah bootstrap belum memicu peralihan ke `full`.
- OCR gambar (P1); klasifikasi hanya 2 MB pertama teks per file.
- Metrik posture data-at-rest (exposure tinggi per domain) di dashboard tiket 20.
- Ekstraksi masih di proses worker (di gVisor), belum service antrean terpisah seperti tabel §5.
- Remediation (tiket 33): `Remediate` masih `ErrNotSupported`.