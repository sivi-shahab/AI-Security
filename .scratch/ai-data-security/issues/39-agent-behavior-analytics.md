# 39: Agent behavior analytics

Status: needs-triage
Type: task
Priority: P2
Milestone: M4
Blocked by: 28
Spec: `../spec.md` §3.1 P2; ASI08, ASI10

## Konteks
Deteksi rogue agent dan cascading failure dari pola tool call.

## Scope
- Baseline urutan tool call per agent.
- Deteksi anomali (tool baru, lonjakan volume, urutan tidak lazim) → event dan risk signal.

## Acceptance criteria
- [ ] Evaluasi pada skenario rogue agent sintetis.
- [ ] Alert terhubung ke incident.
