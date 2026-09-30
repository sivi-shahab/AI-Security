# 17: Risk scoring v1 + critical overrides

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 11
Spec: `../spec.md` §4.9 FR-RISK-1..4

## Konteks
Severity incident dan sebagian policy bergantung pada skor risiko.

## Scope
- Implementasi rumus berbobot (f_sens, f_dest, f_attack, f_agency, f_volume, f_ident).
- Critical overrides FR-RISK-2.
- Bobot dan override berversi, dapat disimulasikan seperti policy.
- Skor agregat per user/app/agent dengan half-life 14 hari.

## Acceptance criteria
- [ ] Test tabel untuk setiap faktor dan setiap override.
- [ ] Skor selalu dalam 0–100 (property test).
- [ ] Versi bobot tercatat di setiap event.
