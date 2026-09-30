# 20: Posture dashboard v1

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 16, 17, 18
Spec: `../spec.md` §4.11 FR-COMP-5; §1.5

## Konteks
CISO butuh gambaran posture dan tren.

## Scope
- Skor posture per domain (discovery, data, prompt, agent, policy hygiene) + tren 90 hari.
- Top risks, shadow AI top apps, exception yang akan kedaluwarsa.
- Metrik sukses §1.5 yang sudah bisa diukur di M1.

## Acceptance criteria
- [ ] Dashboard dapat diakses sesuai RBAC (CISO read-only).
- [ ] Angka dashboard cocok dengan query langsung ke store analitik (test rekonsiliasi).
