# ADR-0001: Hosting, data residency, cakupan build, dan tenancy

Status: accepted
Tanggal: 2026-10-02
Tiket: `.scratch/ai-data-security/issues/01-keputusan-hosting-data-residency-build-vs-buy.md`
Spec: §10.2, §12.1, §18 (U3, U4, U7, U11), §19 (DEC-5)

## Konteks
Arsitektur M1 terkunci oleh empat hal: tooling keamanan yang sudah dimiliki bank (build vs buy), lokasi hosting, aliran data yang keluar dari Indonesia, dan tenancy. Inventaris SWG/CASB/DLP belum tersedia saat keputusan ini dibuat, sehingga keputusan cakupan build bersandar pada asumsi eksplisit yang harus diverifikasi.

## Keputusan

### ASM-5: Inventaris vendor belum diketahui
Kita anggap **belum ada modul AI vendor (SWG/CASB/DLP) yang dilisensikan dan aktif**, dan log proxy/SWG/DNS bisa diekspor (cukup untuk tiket 03).
Verifikasi: tim infra/procurement menyerahkan daftar vendor per lapisan (SWG, CASB, DLP, endpoint/browser management) beserta status modul AI-nya (dilisensikan / aktif / tidak ada).

### DEC-5: Cakupan build v1 = fokus inti
Dibangun: AI Gateway, MCP Gateway, detektor lokal L1/L2, policy engine (OPA), audit log, incident, compliance layer, dan connector data-at-rest.
Shadow AI v1 hanya **pasif** dari log proxy/SWG/DNS (tiket 03, 16).
Ditunda ke M3+ dan dievaluasi ulang setelah ASM-5 terverifikasi: browser extension (22), ICAP adapter (23), endpoint agent (36). Event dari vendor nantinya dikonsumsi lewat pipeline event yang sama (tiket 15).

Ditolak:
- **Build penuh.** Membangun ulang enforcement inline yang besar kemungkinan sudah ada di SWG/CASB komersial. Risiko usaha terbuang tinggi bila ASM-5 salah.
- **Minimal (gateway + detektor saja).** Membuang agent/MCP governance dan compliance, padahal keduanya nilai diferensiasi utama (§19).

### U3: Hosting on-prem di DC dan DRC bank, cloud-portable
Kubernetes di DC bank dengan DRC di DC cadangan bank. Komponen hanya OSS standar §12.1 (Kafka/Redpanda, PostgreSQL + Patroni, OpenSearch, Redis, OPA, object storage S3-compatible dengan object lock). Tidak memakai managed service yang mengunci ke satu cloud.
Alasan: tidak menambah penyedia jasa TI baru di luar bank, langsung memenuhi syarat DC/DRC di Indonesia (POJK 11/2022), dekat dengan aplikasi AI internal dan sumber data, dan target v1 berjalan di CPU (ONNX int8) sehingga tidak butuh GPU cloud.

Ditolak:
- **Cloud region Indonesia.** Menambah penyedia jasa TI baru beserta kewajiban pelaporan ke OJK dan due diligence vendor. Bank belum punya landing zone cloud yang diketahui sudah disetujui.
- **Hybrid.** Dua model operasional dan konektivitas antar-lokasi tanpa kebutuhan nyata saat ini.

Konsekuensi: tim platform internal MUST sanggup mengoperasikan Kafka, PostgreSQL HA, dan OpenSearch. Bila tidak sanggup, ini menjadi pemicu review.

### U4: Data residency
1. **Platform tidak memiliki komponen, penyimpanan, atau telemetri konten di luar Indonesia.** Feed eksternal (katalog AI app, threat intel, model detektor) hanya *pull* masuk dan diverifikasi signature-nya. Tidak ada konten yang dikirim keluar untuk keperluan platform (selaras dengan DEC-4).
2. **Aliran prompt ke LLM provider offshore diatur lewat katalog dan policy, bukan dilarang total.**
   - `AI_APP` mencatat `hosting_region` (sudah ada) dan field baru `ojk_approval_ref` (referensi persetujuan/pelaporan OJK atau penilaian compliance; null bila belum ada).
   - Default policy untuk destinasi dengan `hosting_region` di luar Indonesia:

     | Sensitivity konten (FR-CLS-3) | Aksi default |
     |---|---|
     | `restricted` | block |
     | `confidential` (termasuk data pribadi nasabah dan data spesifik bank) | redact atau tokenize; block bila redaction tidak memungkinkan |
     | `internal`, `public` | allow, hanya bila app berstatus `sanctioned` |

   - Setiap keputusan tercatat di audit log sebagai bukti untuk OJK / UU PDP.

Ditolak:
- **Block semua LLM offshore.** Mematikan adopsi layanan enterprise (Copilot, ChatGPT Enterprise) yang mungkin sudah direncanakan (U8).
- **Platform tidak ikut mengatur residency.** Membuang salah satu nilai diferensiasi (§19) dan bukti kepatuhan.

Keabsahan memproses data di provider tertentu adalah keputusan compliance per app. Platform menegakkan dan membuktikannya, tidak memutuskannya.

### U11: Single-tenant, tenant-aware (ASM-4 dikonfirmasi)
Satu deployment untuk bank. `tenant_id` + RLS PostgreSQL di semua tabel dan HMAC per tenant tetap dipertahankan sebagai defense-in-depth. Fitur produk multi-tenant (onboarding tenant, billing, isolasi per-tenant di infrastruktur) tidak dibangun.

## Pemicu review

| Keputusan | Ditinjau ulang bila |
|---|---|
| ASM-5, DEC-5 | Inventaris vendor didapat dan ternyata ada modul AI yang aktif atau dilisensikan |
| U3 | Bank menyetujui landing zone cloud Indonesia, atau tim platform tidak sanggup mengoperasikan stack OSS |
| U4 | Ada perubahan regulasi OJK / UU PDP, atau provider utama membuka region Indonesia |
| U11 | Ada entitas grup / anak usaha yang akan ikut memakai platform |

## Dampak ke tiket
- 22, 23, 36: ditunda ke M3+ dan dievaluasi ulang setelah ASM-5 terverifikasi.
- 16: tambah field `ojk_approval_ref` pada `AI_APP`.
- 11, 13: template default policy residency (tabel U4) dan penegakannya di AI Gateway.
- 02, 05: tidak lagi terblokir.
