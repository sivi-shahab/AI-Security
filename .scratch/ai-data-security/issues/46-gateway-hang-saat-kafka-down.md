# 46: AI gateway berhenti melayani saat Kafka tidak tersedia

Status: needs-triage
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
- [ ] Dengan Kafka mati, request lewat gateway tetap selesai (p99 overhead ≤ 200 ms) dan event yang tidak terkirim terhitung di metrik dan alert.
- [ ] `deploy/nfr/chaos.sh` skenario Kafka hijau.
