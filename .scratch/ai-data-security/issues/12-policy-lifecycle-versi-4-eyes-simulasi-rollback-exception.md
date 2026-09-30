# 12: Policy lifecycle: versi, 4-eyes, simulasi, rollback, exception

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 11, 15
Spec: `../spec.md` §4.7 FR-POL-5..7; §8.3

## Konteks
Admin DLP harus bisa mengubah kebijakan dengan aman.

## Scope
- State `draft → simulated → pending_approval → active → retired`; author ≠ approver.
- Simulasi terhadap event 7–30 hari + corpus, dengan diff keputusan (`POST /policies/{id}/simulate`).
- Mode monitor-only per rule.
- Rollback ke versi sebelumnya dalam 1 aksi.
- Exception dengan scope, approver, dan kedaluwarsa wajib (default maks 90 hari), notifikasi 7 hari sebelum kedaluwarsa.

## Acceptance criteria
- [ ] Propagasi publish/rollback ke semua PEP ≤ 60 s p99.
- [ ] Publish tanpa approver kedua ditolak.
- [ ] Exception tanpa `expires_at` ditolak.
- [ ] Semua transisi tercatat di audit log.
