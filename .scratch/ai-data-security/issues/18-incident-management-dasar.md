# 18: Incident management dasar

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 15, 17
Spec: `../spec.md` §4.10 FR-INC-1..4, FR-INC-7; §8.5

## Konteks
SOC butuh tempat triage.

## Scope
- State machine (FR-INC-3) dan severity dari skor.
- Dedup `(principal, destination, class, policy_id)` dalam window 30 menit.
- Evidence redacted; raw hanya jika `forensic_capture` aktif (terenkripsi per incident, unmask dengan justifikasi).
- SLA timer acknowledge (critical ≤ 15 menit, high ≤ 1 jam).
- API incidents + transition.

## Acceptance criteria
- [ ] Test transisi state valid dan invalid.
- [ ] Test dedup window.
- [ ] Akses unmask tanpa permission/justifikasi ditolak dan tercatat.

## Out of scope
Korelasi lintas sesi agent, breach timer, dan SOAR/ITSM (tiket 26).
