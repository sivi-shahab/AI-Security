# 21: NFR gate M1: load, soak, chaos, DR

Status: needs-triage
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
- [ ] Laporan hasil vs target §13.1.
- [ ] Semua deviasi punya tiket atau keputusan terima risiko.
