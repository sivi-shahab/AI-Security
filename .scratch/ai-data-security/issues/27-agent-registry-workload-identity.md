# 27: Agent registry & workload identity

Status: needs-triage
Type: task
Priority: P1
Milestone: M3
Blocked by: 06, 11
Spec: `../spec.md` §4.8 FR-AGT-1, FR-AGT-2; §6

## Konteks
Fondasi governance agent.

## Scope
- Registry: owner, purpose, model, tools+scopes, data scopes, risk tier, status.
- Agent tanpa owner otomatis `quarantined`.
- Workload identity (SPIFFE/OIDC client/managed identity); kredensial user bersama dilarang.
- Antrean review untuk shadow agent (dari MCP traffic dan OAuth grant).

## Acceptance criteria
- [ ] Metrik 'agent tanpa owner & policy' = 0 dapat diukur.
- [ ] Semua perubahan registry tercatat di audit log.
