# 48: Latensi AI gateway naik ~400 ms saat Redis tidak tersedia

Status: needs-triage
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
- [ ] `deploy/nfr/chaos.sh` skenario Redis: overhead p95 ≤ 80 ms, p99 ≤ 200 ms selama Redis mati.
- [ ] Tidak ada 503 untuk app `fail_closed` selama Redis mati, diulang ≥ 5 kali dari start bersih.
