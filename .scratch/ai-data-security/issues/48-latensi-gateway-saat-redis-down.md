# 48: Latensi AI gateway naik ~400 ms saat Redis tidak tersedia

Status: needs-triage
Type: bug
Priority: P2
Milestone: M2
Blocked by: -
Spec: `../spec.md` §13.1 (overhead p95 ≤ 80 ms, p99 ≤ 200 ms); §13.3; temuan tiket 21 (`docs/nfr/m1-report.md`)

## Konteks
Chaos tiket 21: dengan Redis mati, request tetap dilayani (limit tidak ditegakkan dan dicatat, sesuai desain `withinLimits`), tetapi p95 naik dari 26 ms menjadi **416 ms** (p99 440 ms) karena setiap request menunggu dial/read timeout bawaan go-redis untuk rate counter dan quota. Ada 7.192 baris error log dalam 30 detik.

## Scope
- Timeout Redis pendek (dial/read ≤ 50 ms) di `cmd/ai-gateway`, plus circuit breaker: setelah N kegagalan, lewati Redis selama T detik dan pakai counter per replika (`MemoryCounter`) sebagai degradasi.
- Log yang dibatasi (rate-limited) dan metrik `rate_counter_unavailable_total` + alert, bukan satu error per request.

## Acceptance criteria
- [ ] `deploy/nfr/chaos.sh` skenario Redis: overhead p95 ≤ 80 ms, p99 ≤ 200 ms selama Redis mati.
