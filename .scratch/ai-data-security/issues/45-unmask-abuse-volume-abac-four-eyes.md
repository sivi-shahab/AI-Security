# 45: Kontrol abuse unmask evidence: alert volume, ABAC, four-eyes

Status: needs-triage
Type: task
Priority: P1
Milestone: M2
Blocked by: 18
Spec: `../spec.md` §10.1 AuthZ (ABAC); FR-INC-4; `docs/threat-model.md` §4.5, G6

## Konteks
Threat model (tiket 02) G6: unmask sudah butuh permission, step-up, justifikasi, dan diaudit. Namun belum ada deteksi volume/pola per analis, pemeriksaan memakai `authz.Resource{}` kosong (ABAC unit/region tidak membatasi), dan tidak ada four-eyes untuk evidence `restricted`.

## Scope
- Alert bila unmask per analis melewati ambang per hari, atau menyasar principal yang sama berulang kali.
- ABAC: atribut unit bisnis/region insiden dibandingkan dengan atribut analis.
- Evidence `restricted`: unmask butuh persetujuan analis kedua.

## Acceptance criteria
- [ ] Analis di luar unit/region insiden ditolak (test), dan penolakan diaudit.
- [ ] Alert volume unmask di `deploy/cluster/alerts.yaml` dengan test metrik.
- [ ] Unmask evidence `restricted` tanpa approver kedua ditolak.
