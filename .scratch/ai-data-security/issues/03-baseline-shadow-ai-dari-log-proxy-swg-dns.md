# 03: Baseline shadow AI dari log proxy/SWG/DNS

Status: needs-triage
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
- [ ] Laporan baseline shadow AI untuk ≥ 30 hari log tersedia.
- [ ] Unit test untuk rumus confidence dan matcher fingerprint.
- [ ] Tidak ada identitas user plaintext di output (HMAC).

## Out of scope
Inline enforcement dan konteks personal/corporate account (butuh proxy inline, tiket 22/23).

## Catatan dari ticket 16
- Sudah ada: seed katalog (15 app, `internal/catalog/seed.json`), matcher fingerprint + rumus confidence (`internal/catalog/match.go`, dites), dan `APP_USAGE_DAILY`. Ticket ini tinggal ingest log batch, memperluas seed ke ~200 app, dan laporan baseline.

