# 30: HITL approval & kill switch

Status: needs-triage
Type: task
Priority: P1
Milestone: M3
Blocked by: 28
Spec: `../spec.md` §4.8 FR-AGT-6, FR-AGT-7; §8.6

## Konteks
Aksi agent berisiko tinggi butuh manusia, dan harus ada tombol darurat.

## Scope
- `APPROVAL_REQUEST` dengan preview aksi dan parameter (redacted sesuai hak); timeout → deny.
- Kanal approval: UI + notifikasi (email/chat).
- Kill switch per agent/tool/app/global: cabut token, putus sesi, push policy block.

## Acceptance criteria
- [ ] Kill switch efektif ≤ 10 s (diukur).
- [ ] Approval kedaluwarsa → aksi ditolak.
- [ ] Approver tidak bisa menyetujui permintaan agent miliknya sendiri.
