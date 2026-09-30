# 38: Custom classifier per tenant & active learning

Status: needs-triage
Type: task
Priority: P2
Milestone: M4
Blocked by: 09, 10, 25
Spec: `../spec.md` §9.3 isolasi; §9.4

## Konteks
Tuning detektor ke kebutuhan bank tanpa membocorkan data.

## Scope
- Antrean active learning dari feedback triage (redacted).
- Fine-tune per tenant dengan opt-in eksplisit, di dalam tenant boundary.
- Gate rilis model §9.4 + rollout shadow → canary → 100%.

## Acceptance criteria
- [ ] Model tenant tidak dapat diakses lintas tenant (test isolasi).
- [ ] Tidak ada regresi F1/FPR di atas ambang gate.
