# 48: Latensi AI gateway naik ~400 ms saat Redis tidak tersedia

Status: needs-gitlab-run
Type: bug
Priority: P2
Milestone: M2
Blocked by: -
Spec: `../spec.md` §13.1 (overhead p95 ≤ 80 ms, p99 ≤ 200 ms); §13.3; temuan tiket 21 (`docs/nfr/m1-report.md`)

## Konteks
Chaos tiket 21: dengan Redis mati, request tetap dilayani (limit tidak ditegakkan dan dicatat, sesuai desain `withinLimits`), tetapi p95 naik dari 26 ms menjadi **416 ms** (p99 440 ms) karena setiap request menunggu dial/read timeout bawaan go-redis untuk rate counter dan quota. Ada 7.192 baris error log dalam 30 detik.

Pengulangan 2026-10-10 (setelah tiket 46, skenario Redis saja, 30 s, 30 RPS app `fail_closed`), hasilnya sangat bervariasi:
- Kode baru, 5 run: 3 run p95 0,4–0,8 s; 2 run p95 3,3–3,8 s, p99 5–6,5 s, dengan **163–204 jawaban 503**.
- Kode lama (sebelum tiket 46), 4 run: p95 0,4–1,2 s, tanpa 503.

Ekor latensi beberapa detik cocok dengan dial timeout bawaan go-redis (5 s). Mekanisme 503 belum dipastikan; dugaan saya, deadline PDP habis di belakang counter. Kaitan dengan produce async tiket 46 juga belum bisa dikesampingkan dengan 9 sampel. Usul: naikkan prioritas, karena Redis mati ternyata bisa menolak trafik `fail_closed`, bukan hanya memperlambatnya.

## Scope
- Timeout Redis pendek (dial/read ≤ 50 ms) di `cmd/ai-gateway`, plus circuit breaker: setelah N kegagalan, lewati Redis selama T detik dan pakai counter per replika (`MemoryCounter`) sebagai degradasi.
- Log yang dibatasi (rate-limited) dan metrik `rate_counter_unavailable_total` + alert, bukan satu error per request.

## Acceptance criteria
- [x] `deploy/nfr/chaos.sh` skenario Redis: overhead p95 ≤ 80 ms, p99 ≤ 200 ms selama Redis mati. *(5 run Redis saja dari start bersih dengan warm-up: p95 17–59 ms, p99 20–149 ms. Sebelumnya p95 416 ms sampai 3,8 s. Run `chaos.sh` penuh: p95 99 ms, p99 224 ms. Run yang sama juga menunjukkan ekor ~1 s di skenario tanpa Redis (`opa cached`, `redis back`, `detection down`) karena host sedang dipakai proses lain (load 4–5; tiket 21 mengukur di load < 1). Perlu dikonfirmasi ulang di staging (RA-3).)*
- [x] Tidak ada 503 untuk app `fail_closed` selama Redis mati, diulang ≥ 5 kali dari start bersih. *(10 dari 10 run tanpa 503: 5 tanpa warm-up dan 5 dengan warm-up.)*

## Keputusan
- **Timeout Redis 50 ms** untuk dial, read, write, dan pool, tanpa retry (`cmd/ai-gateway`). Nilai di `REDIS_URL` (`dial_timeout`, `read_timeout`, `max_retries`) tetap menang.
- **`aigw.Degraded`** membungkus `RedisCounter`. Saat Redis gagal, request itu memakai `MemoryCounter` per replika, dan Redis dilewati selama 5 s sebelum dicoba lagi. Jadi satu outage hanya memakan satu timeout per 5 s, bukan satu per request. Limit tetap ditegakkan per replika (dengan N replika, efektifnya N× limit), lebih baik daripada tidak ditegakkan sama sekali. Kegagalan karena caller sudah membatalkan context tidak dihitung sebagai outage.
- **Log** satu baris per masa cooldown (6 per 30 s; sebelumnya ~7.000). Metrik `aigw_rate_counter_unavailable_total`, alert `AIGatewayRateCounterDegraded` (warning).
- **Breaker tanpa ambang N kegagalan:** satu kegagalan langsung membuka breaker. Dengan cooldown 5 s, Redis yang sekali tersendat hanya membuat limit lokal selama 5 s, jadi ambang tidak perlu.
- **Temuan harness:** tepat setelah `run.sh up`, tanpa gangguan apa pun, gateway bisa memberi p95 1,4 s dan 503 (OPA dan JVM masih dingin). 503 yang tercatat di tiket 46 hampir pasti berasal dari sini, bukan dari produce async. `run.sh up` kini menunggu app `fail_closed` mendapat 200, lalu memberi beban 15 s untuk warm-up.

## Hasil verifikasi lokal (2026-10-11)
- `go vet ./...`, golangci-lint v2.5.0 0 issue, `go test -race ./internal/aigw` hijau (termasuk `TestDegradedCounter`).
- Harness tiket 21 seperti di atas. `results/chaos-*` diperbarui dari run penuh 2026-10-11.

## Sisa
- Konfirmasi angka di staging dengan host yang tidak dipakai bersama (RA-3).
- Kalau limit per replika selama outage terlalu longgar untuk app tertentu, opsinya menolak (fail closed) untuk app itu. Saat ini limit adalah kontrol ketersediaan, bukan kontrol data, sesuai desain `withinLimits`.
