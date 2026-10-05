# 34: Compliance module: framework library, evidence, report

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M3
Blocked by: 07, 18
Spec: `../spec.md` §4.11 FR-COMP-1..3; §14

## Konteks
Bukti kepatuhan untuk OJK, UU PDP, dan ISO 42001.

## Scope
- Framework library berversi (OWASP LLM/ASI, NIST AI RMF/600-1, ISO 42001, UU PDP + PP 33/2026, POJK 11, Panduan AI OJK).
- Mapping kontrol ↔ requirement; verifikasi nomor subkategori/klausul oleh tim compliance.
- Evidence otomatis dari konfigurasi, policy aktif, statistik enforcement, dan hasil test.
- Riwayat status kontrol + export per periode audit.
- AI inventory/register untuk kebutuhan OJK/ISO 42001.

## Acceptance criteria
- [ ] Mapping §14 terverifikasi terhadap teks resmi. *(**Separuh: pra-verifikasi riset selesai, sign-off tim compliance belum.** Setiap sel §14 sudah dicek terhadap teks resmi yang bisa diambil pada 2026-10-05: OWASP LLM 2025 (genai.owasp.org), NIST AI RMF Core (airc.nist.gov), UU 27/2022 (peraturan.bpk.go.id), POJK 11/POJK.03/2022 dan Panduan AI OJK (ojk.go.id), PP 33/2026 (salinan pemerintah). Koreksi masuk ke library dan §14 spec, antara lain: GOVERN 4/MEASURE 4 untuk audit log **salah** dan diganti; GOVERN 6 → GOVERN 1.1; ASI07 → ASI02; pasal POJK dibuat spesifik; **POJK 11 Pasal 60 (notifikasi insiden ke OJK 24 jam) ditambahkan**. Setiap mapping menyimpan putusan, sumber, dan catatannya. Yang tidak bisa diverifikasi dari sumber bebas: **semua sel ISO/IEC 42001** (berbayar) dan judul ASI01–ASI10 (PDF OWASP terkunci formulir). AC ini selesai saat tim compliance menandatangani tiap mapping lewat `POST /compliance/mappings/verify` (laporan menampilkan `mappings_verified` n/m).)*
- [x] Export laporan untuk satu periode audit sampel. *(`TestExportAndVersions`: periode Q3 2026 (1 Jul–1 Okt) dengan status kontrol di awal/akhir, transisi (rule injection dinonaktifkan 11 Jul → partial), ringkasan bukti otomatis, lampiran (laporan AgentDojo), mapping per requirement dengan putusan riset dan sign-off; JSON ber-SHA-256 dan CSV; setiap export diaudit.)*
- [x] Perubahan versi framework tidak menghapus riwayat lama. *(Versi baru = baris baru; versi lama, mapping, dan sign-off-nya tetap; dokumen versi yang sudah tersimpan tidak bisa diubah tanpa nomor versi baru; export periode lama setelah versi baru tetap memakai versi lama dengan angka sign-off yang sama; seluruh tabel compliance append-only (trigger menolak UPDATE/DELETE). Uji mutasi (selalu memakai versi terbaru) membuat test gagal.)*

## Keputusan
- **Library berversi** (`internal/compliance/library`): OWASP LLM 2025, OWASP Agentic 2026, NIST AI RMF 1.0, ISO/IEC 42001:2023 Annex A (hanya ID; judul "to be confirmed"), UU PDP 27/2022, PP 33/2026, POJK 11/POJK.03/2022, Panduan Tata Kelola Kecerdasan Artifisial Perbankan Indonesia (OJK, 29 April 2025). Hanya ID dan judul ringkas/kutipan pendek, tanpa teks berlisensi. Library ter-embed diimpor saat start; versi baru menambah baris, versi lama tidak pernah dihapus atau diubah. EU AI Act tidak dimasukkan (cakupan bank `unspecified`).
- **Mapping** membawa riset (`supported` | `weak` | `unverifiable`, sumber, catatan). Sel yang `wrong` tidak dimasukkan dan diganti. Riset **bukan sign-off**: status `verified`/`rejected` hanya dari tim compliance (`compliance.write`, DPO) dengan sumber resmi wajib (URL, pasal/ayat, klausul); diaudit; sign-off terikat ke versi framework tempat ia dibuat.
- **Kontrol platform** = baris §14, ditambah `CTL-DATA` (data-at-rest, tiket 31–33) yang ditandai *proposed*. Library menolak kontrol tanpa mapping (FR-COMP-2).
- **Bukti otomatis** setiap jam (dan `POST /compliance/collect`), dari:
  - rule yang di-enforce di rilis policy aktif (DLP, injection, agent, MCP, rate, residency);
  - metrik posture (inventaris, app offshore tanpa persetujuan OJK);
  - registry agent (agent tanpa owner/allow-list, kill switch aktif) dan tool MCP yang under review;
  - SLA insiden;
  - verifikasi hash chain audit 24 jam terakhir;
  - scan dan exposure data-at-rest, serta remediasi yang dijalankan.

  Aturan status sederhana dan bisa dihitung ulang auditor. Sumber yang gagal → `unknown` beserta alasannya. Lampiran (hash + catatan) untuk hasil test atau dokumen. Bagian yang belum ada dinyatakan `partial`: quota token AI gateway (tiket 13) dan timer breach UU PDP (tiket 26).
- **Riwayat**: satu baris bukti per pengumpulan, satu baris status hanya saat status atau alasannya berubah; semua append-only.
- **Export** (`GET /compliance/report?from=&to=[&format=csv]`): versi framework yang berlaku di akhir periode (versi lain yang berlaku di dalam periode disebut), status awal/akhir dan transisi per kontrol, ringkasan dan hash bukti, lampiran, mapping dengan riset dan sign-off per akhir periode, SHA-256 laporan; dibangun dari snapshot read-only; diaudit.
- **AI register** (`GET /compliance/ai-register[?format=csv]`): app AI (katalog: sanction, region hosting, referensi persetujuan OJK, training), agent (owner, unit, tujuan, risk tier, status), tool MCP, dan layanan AI enterprise yang dipantau lewat Compliance API.
- API: baca dengan `compliance.read` (CISO, DPO, auditor); tulis (sign-off, lampiran, collect) dengan `compliance.write` (DPO).

## Hasil verifikasi lokal (2026-10-05)
- `go test -race ./...` dengan Postgres, MinIO, dan Azurite hijau; golangci-lint 0 issue; image `control-plane` ter-build.

## Sisa / follow-up
- **Sign-off tim compliance** atas setiap mapping (AC pertama), termasuk konfirmasi ISO/IEC 42001 terhadap salinan berlisensi dan judul ASI dari PDF OWASP resmi; identifikasi pasal transfer di PP 33/2026; tanggal berlaku PP 33/2026 (sumber sekunder: 16 Jan 2027).
- Subkategori yang lebih ketat dari riset (MAP 1.1, MANAGE 1.3, GOVERN 1.5, MANAGE 3.1, GOVERN 6.1, MAP 4.1) dan teks resmi MEASURE 2.8 dan MANAGE 4.1 belum dikutip: rilis versi library berikutnya setelah dicek.
- Timer notifikasi OJK 24 jam (POJK 11 Ps. 60) perlu masuk ke alur insiden (tiket 26) bersama 3×24 jam UU PDP.
- Laporan kondisi TI tahunan (POJK 11 Ps. 59) sebagai template export.