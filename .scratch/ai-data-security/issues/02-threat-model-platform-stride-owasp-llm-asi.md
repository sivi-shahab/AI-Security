# 02: Threat model platform (STRIDE + OWASP LLM/ASI)

Status: needs-triage
Type: task
Priority: P0
Milestone: M0
Blocked by: 01
Spec: `../spec.md` §3.2 DoD #4; §4.5; §4.8; §14

## Konteks
DoD mensyaratkan threat model per fitur. Baseline threat model untuk seluruh platform dibutuhkan sebelum M1.

## Scope
- STRIDE per komponen §5.2: PEP, detection, OPA, control plane, analytics.
- Mapping ancaman ke OWASP LLM01–LLM10 dan ASI01–ASI10 beserta kontrol spec yang menanganinya.
- Threat model khusus: bypass gateway, bundle policy palsu, kebocoran lewat log/telemetry, tenant crossover, dan abuse unmask evidence.

## Acceptance criteria
- [ ] Dokumen threat model ada di `docs/`.
- [ ] Setiap ancaman high punya kontrol atau tiket mitigasi.
- [ ] Gap dicatat sebagai tiket baru.
