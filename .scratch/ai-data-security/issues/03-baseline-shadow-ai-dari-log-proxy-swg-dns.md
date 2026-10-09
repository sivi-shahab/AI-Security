# 03: Baseline shadow AI dari log proxy/SWG/DNS

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M0
Spec: `../spec.md` §4.1 FR-DISC-2, FR-DISC-3; §4.2 FR-SHADOW-1, FR-SHADOW-4; §11

## Konteks
Mengukur baseline pemakaian AI sebelum enforcement. Baseline ini dipakai untuk metrik sukses §1.5.

## Scope
- Ingest batch log SWG/proxy/firewall/DNS yang sudah ada (syslog/file).
- Fingerprinting domain/SNI + URL pattern terhadap seed katalog AI (top ~200 app GenAI).
- Confidence scoring `1 − Π(1 − c_i)` dan antrean review untuk confidence < 0,6.
- Laporan: top apps, top users/unit (pseudonim), dan tren mingguan.

## Acceptance criteria
- [ ] Laporan baseline shadow AI untuk ≥ 30 hari log tersedia. *(Alat siap dan teruji pada log sintetis 35 hari (`TestBaseline35Days`) serta smoke run 31 hari `.gz`. Laporan nyata menunggu ekspor ≥ 30 hari log SWG/proxy/DNS dari bank; laporan menandai sendiri bila log < 30 hari.)*
- [x] Unit test untuk rumus confidence dan matcher fingerprint. *(Sudah ada dari tiket 16 (`internal/catalog`); ditambah `TestSeedCatalog`: domain unik per app di seed 199 app, endpoint regional Bedrock/Vertex/Azure OpenAI ter-resolve, SaaS umum tidak cocok.)*
- [x] Tidak ada identitas user plaintext di output (HMAC). *(User/IP di-HMAC dengan `TENANT_PEPPER` saat dibaca; pepper < 16 byte ditolak. Test memastikan tidak ada nama user atau IP klien di JSON maupun Markdown.)*

## Out of scope
Inline enforcement dan konteks personal/corporate account (butuh proxy inline, tiket 22/23).

## Catatan dari ticket 16
- Sudah ada: seed katalog (15 app, `internal/catalog/seed.json`), matcher fingerprint + rumus confidence (`internal/catalog/match.go`, dites), dan `APP_USAGE_DAILY`. Ticket ini tinggal ingest log batch, memperluas seed ke ~200 app, dan laporan baseline.


## Keputusan
- **CLI batch `cmd/shadow-baseline`**, bukan service: baseline fase 0 diambil sebelum platform inline berjalan, dari file log yang sudah ada (plain atau `.gz`, atau stdin). Output: `shadow-baseline.json` (untuk alat) dan `shadow-baseline.md` (untuk manusia).
- **Format:** Squid native access log, BIND query log (juga di balik prefix syslog RFC 5424), dan JSON lines dengan pemetaan field (`-fields time=ts,user=login,...`) untuk ekspor Zscaler NSS/Netskope/Palo Alto/Fortinet. Baris syslog BSD tanpa tahun dihitung tidak terbaca. CSV dan format vendor native menyusul bila bank memakainya.
- **Fingerprint** memakai matcher katalog tiket 16 apa adanya. Host di luar katalog yang namanya mengindikasikan AI (`.ai`, `gpt`, `llm`, `chatbot`, `copilot`, `genai`) masuk antrean review dengan confidence 0,3. Dari sinilah shadow AI yang belum dikatalogkan terlihat.
- **Antrean review** = bagian laporan (host, confidence, sinyal, kandidat, jumlah user/request). Penyelesaiannya lewat katalog yang sudah ada (`POST /apps` atau koreksi app); tidak ada endpoint baru.
- **Seed katalog 15 → 199 app** (version 2), hanya domain publik. SaaS umum yang menyematkan AI (Notion, Canva, Zoom, Bing) sengaja tidak dimasukkan: mencocokkan seluruh domainnya akan menghitung semua pemakaiannya sebagai AI.
- **Unit** dari CSV `user,unit` opsional (bisa juga IP klien → unit). Unit bersifat organisasional, bukan identitas personal.

## Sisa
- Jalankan pada ekspor log bank ≥ 30 hari, lalu tinjau antrean review dan beri status sanction untuk top apps (metrik §1.5).
