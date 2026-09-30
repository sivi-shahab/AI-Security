# 11: OPA PDP: input kanonik, precedence, bundle bertanda tangan

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 05
Spec: `../spec.md` §4.7 FR-POL-1..4, FR-POL-9; §13.1

## Konteks
Satu PDP untuk semua PEP (prinsip P2).

## Scope
- Skema input/output kanonik (FR-POL-2/3) sebagai JSON Schema berversi.
- Library Rego untuk precedence: `block > quarantine > require_approval > tokenize > redact > warn > allow` + penggabungan obligations.
- Policy Service membangun dan menandatangani bundle; OPA sidecar memverifikasi dan melakukan long-poll.
- Decision log dengan masking field sensitif.
- Template kebijakan bawaan (FR-POL-8).

## Acceptance criteria
- [ ] `opa test` untuk precedence dan setiap template.
- [ ] `opa bench`: eval p99 ≤ 5 ms di sidecar.
- [ ] Bundle dengan signature tidak valid ditolak dan memicu alert.
