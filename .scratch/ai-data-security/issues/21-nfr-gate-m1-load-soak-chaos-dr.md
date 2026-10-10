# 21: NFR gate M1: load, soak, chaos, DR

Status: needs-signoff
Type: task
Priority: P0
Milestone: M1
Blocked by: 13, 14, 15, 18
Spec: `../spec.md` §12.1 DR; §13; §15

## Konteks
Gate sebelum MVP dipakai produksi.

## Scope
- Load test ke target §13.1 + soak 24 jam.
- Chaos: matikan OPA, detection, Kafka, dan Redis; verifikasi fail mode.
- DR drill Postgres + object storage; ukur RPO ≤ 15 menit dan RTO ≤ 4 jam.
- Sizing awal berdasarkan ASM-2.

## Acceptance criteria
- [x] Laporan hasil vs target §13.1. *(`docs/nfr/m1-report.md`: setiap baris §13.1 dengan angka terukur, metode, data mentah di `deploy/nfr/results/`, dan keterbatasan host.)*
- [ ] Semua deviasi punya tiket atau keputusan terima risiko. *(Tujuh deviasi punya tiket baru: 46 Kafka mati → gateway berhenti melayani (P0), 47 OPA p99 dan throughput per pod, 48 latensi saat Redis mati, 49 L2/detection-svc tidak di jalur PEP, 50 scan file hanya 2 MiB pertama, 51 fail mode bundle > 24 jam. Tiga hal lain (RA-1 availability via SLO produksi, RA-2 soak 24 jam di staging sebelum rollout luas, RA-3 ulang di staging dengan mTLS/SASL/L2) ditulis sebagai **usulan keputusan** dan menunggu sign-off pemilik risiko. AC ini tercentang setelah sign-off.)*

## Keputusan
- **Harness:** `deploy/nfr/` berisi Docker Compose dari image service repo (gateway + sidecar OPA dengan bundle bertanda tangan dan `persist`, Kafka, karapace, Redis, OpenSearch, event-ingest, detection-svc, mock provider), satu tool Go `deploy/nfr/nfr` (mock, file server bundle, pembuat bundle, load generator open/closed loop, latensi event → OpenSearch, timing file scan), serta skrip `run.sh`, `measure.sh`, `opa-bench.sh`, `chaos.sh`, `soak.sh`, `dr.sh`, `timing-tests.sh`. Pod uji = gateway 3 vCPU + OPA 1 vCPU (4 vCPU §13.1). Flag dev hanya yang sudah disediakan service.
- **Overhead** diukur sebagai selisih beban yang sama lewat gateway vs langsung ke mock. Propagasi policy dan kill switch memakai test yang sudah mengukurnya (`TestPropagation`, `TestKillSwitchPropagation`, `mcpgw TestKillSwitch`), dijalankan ulang di host yang sepi.
- **Topic event** dibuat oleh platform di produksi. Harness membuatnya (3 partisi) karena tanpa topic setiap `Emit` menunggu 2 detik di jalur request. Temuan ini mengarah ke tiket 46.
- Status `needs-signoff` karena usulan RA-1..3 butuh keputusan manusia. Tidak ada risiko yang diterima atas nama pemilik risiko.

## Hasil verifikasi lokal (2026-10-10)
Host 16 vCPU / 15 GB, satu-satunya beban berat. Ringkas (detail di laporan):
- Overhead 20 RPS: 1K tok p95 +19,6 ms / p99 +22,5 ms; 8K tok p95 +22,2 ms / p99 +24,9 ms ✅. Streaming +17,7 ms per jawaban 20 chunk ✅.
- OPA `opa bench` 1 vCPU p99 9,0 ms ❌. Throughput pod sehat 60 RPS (manifest split) / 100 RPS (OPA 3 vCPU) vs 300 ❌.
- File scan 5 MB p95 0,38 s, 49 MB 0,37 s ✅*, tapi hanya 2 MiB teks pertama yang diperiksa (tiket 50).
- Propagasi policy p99 15,2 s ✅. Kill switch 1,19 s ✅. Event → OpenSearch p95 4,8 s ✅.
- Chaos: OPA mati dan cache bundle sesuai §13.3 ✅. Kafka mati: gateway berhenti melayani ❌. Redis mati: p95 416 ms ❌. detection-svc tidak di jalur PEP ❌.
- Soak 30 menit pada 50 RPS: 0 error, p95 stabil 22–25 ms, memori stabil ✅ (dipersingkat).
- DR (`dr.sh`): Postgres PITR dari MinIO (WAL + base backup), RPO 45,2 s ✅, RTO 20,9 s ✅ (DB kecil; ulangi di DRC dengan ukuran produksi). Bucket audit WORM: delete ditolak, dipulihkan dari replika dalam 6,8 s, isi identik, retensi terpasang ✅.
- Go baru (`deploy/nfr/nfr`): gofmt, `go vet`, golangci-lint v2.5.0 bersih.

## Sisa
- Sign-off RA-1..3 (lihat laporan §6).
- Soak 24 jam: `DURATION=24h deploy/nfr/soak.sh` di staging.
- Ulang `measure.sh`/`chaos.sh` di staging Kubernetes dengan mTLS, SASL/TLS, NetworkPolicy, dan model L2 terpasang.
- Jalur event ke SIEM (siem-export) dan file via Tika belum diukur.
- Setelah tiket 46–51 selesai, jalankan ulang gate.
