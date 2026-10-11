# 46: AI gateway berhenti melayani saat Kafka tidak tersedia

Status: needs-gitlab-run
Type: bug
Priority: P0
Milestone: M1
Blocked by: -
Spec: `../spec.md` §13.1 availability data plane 99,95%; §13.3; temuan tiket 21 (`docs/nfr/m1-report.md`)

## Konteks
Chaos tiket 21: saat broker Kafka dimatikan, **semua** request lewat AI gateway, untuk app `fail_open` maupun `fail_closed`, tidak selesai dalam 30 detik (timeout klien). Request baru selesai setelah Kafka hidup lagi. `Emit` (`cmd/ai-gateway/main.go`) memanggil `Producer.Publish` (`kgo.ProduceSync`) secara sinkron di jalur request dengan context 2 detik. Namun franz-go tidak membatalkan record yang sudah di-buffer atau sedang dikirim ketika context habis, sehingga request menunggu sampai record delivery timeout. Error `context deadline exceeded` baru tercatat setelah broker kembali. Gangguan pada bus event menjadi gangguan data plane.

## Scope
- Lepaskan pengiriman event dari jalur request: produce async (`kc.Produce` + callback) dengan buffer terbatas dan `kgo.RecordDeliveryTimeout`/`ProduceRequestTimeout` pendek. Event yang gagal dicatat ke metrik (`decision_events_dropped_total`) dan alert, atau di-spool ke disk lokal untuk replay.
- Berlaku juga untuk MCP gateway (pola `emit` yang sama).
- Tambah test chaos: broker mati → p99 gateway tetap dalam target dan event yang hilang terhitung.

## Acceptance criteria
- [x] Dengan Kafka mati, request lewat gateway tetap selesai (p99 overhead ≤ 200 ms) dan event yang tidak terkirim terhitung di metrik dan alert. *(Chaos 30 s, 30 RPS per app: 899/899 200 untuk `fail_closed` dan `fail_open`, p95 20 ms, p99 25 ms (total, mock provider menjawab seketika). `decision_events_dropped_total` +3.592, sekitar 2 event per request × 1.798 request. Alert `DecisionEventsDropped` (critical, security) di `deploy/cluster/alerts.yaml`. Unit test `TestPublishKafkaDown`: broker mati, 3 Publish < 100 ms, ketiganya terhitung (2 ditolak karena buffer penuh, 1 setelah delivery timeout), event yang melanggar schema tetap ditolak sinkron.)*
- [x] `deploy/nfr/chaos.sh` skenario Kafka hijau. *(`results/chaos-summary.txt` 2026-10-10; skenario kini mencetak selisih `decision_events_dropped_total`.)*

## Keputusan
- **Akar masalah diperbaiki di `events.Producer.Publish`**, satu-satunya jalur produce kedua gateway: validasi schema tetap sinkron, lalu `TryProduce` ke buffer klien dan langsung kembali, tidak pernah menunggu Kafka. Context record adalah `Background`, karena context request berakhir bersama respons, jauh sebelum record terkirim.
- **Batas:** `MaxBufferedRecords` 10.000 (sekitar 8 menit pada puncak ASM-2 20 RPS × 2 event, puluhan MB) dan `RecordDeliveryTimeout` 30 s. Record yang lebih lama gagal, dan yang baru ditolak saat buffer penuh. Keduanya masuk `decision_events_dropped_total`. Opsi Kafka dari env tetap bisa menimpa.
- **Tanpa spool disk.** Metrik dan alert menandai celah jejak audit. Spool lokal untuk replay baru dibuat kalau outage Kafka yang lebih lama dari buffer ternyata sering terjadi.
- **Metrik:** ai-gateway menambahkannya ke `/metrics` miliknya (`Gateway.Metrics`). mcp-gateway sebelumnya tidak punya `/metrics`, jadi kini memakai `Producer.ServeMetrics`.
- `Close` mengirim isi buffer (maks 5 s) sebelum memutus koneksi, supaya event tidak hilang saat shutdown normal.
- **Harness NFR diperbaiki:**
  - Healthcheck image karapace butuh `KARAPACE_ADVERTISED_PROTOCOL`, dan sekarang di-set.
  - Gateway keluar sampai karapace punya primary, sehingga OPA (yang berbagi network namespace dengan gateway) tersangkut di namespace mati. `run.sh up` sekarang membuat ulang OPA setelah gateway melayani.

## Hasil verifikasi lokal (2026-10-10)
- `go build`, `go vet`, golangci-lint v2.5.0 0 issue. `go test -race` untuk `events`, `aigw`, `mcpgw` hijau, dan `ingest` (Kafka + OpenSearch) hijau.
- Chaos penuh di harness tiket 21: semua skenario sama seperti sebelumnya, kecuali Kafka yang kini hijau. Redis mati menunjukkan variasi besar, dengan 503 di 2 dari 5 run kode baru dan tidak ada di 4 run kode lama. Tiket 48 kemudian menemukan bahwa harness yang baru start memberi 503 bahkan tanpa gangguan apa pun (OPA/JVM dingin), jadi 503 itu hampir pasti bukan akibat perubahan ini.

## Sisa
- MCP gateway tidak punya skenario chaos di harness. Perilakunya mengikuti producer yang sama dan diuji di unit test.
- Scrape `/metrics` gateway oleh Prometheus (ServiceMonitor/PodMonitor) belum ada di `deploy/`, sama seperti metrik gateway lain. Alert baru aktif setelah scrape dipasang.
