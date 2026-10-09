# 02: Threat model platform (STRIDE + OWASP LLM/ASI)

Status: needs-signoff
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
- [x] Dokumen threat model ada di `docs/`. *(`docs/threat-model.md`: aset dan trust boundary, STRIDE per komponen §5.2, mapping LLM01–LLM10 dan ASI01–ASI10 ke kontrol beserta status di kode, serta lima threat model khusus.)*
- [x] Setiap ancaman high punya kontrol atau tiket mitigasi. *(Tabel §5 di dokumen.)*
- [x] Gap dicatat sebagai tiket baru. *(G1–G6 → tiket 40–45.)*

## Hasil
Status `needs-signoff`: dokumen perlu ditinjau CISO/security architect bank. Temuan utama:
- Kontrol MCP/agent (28–30, 39), bundle bertanda tangan (11), audit (07), dan privasi log sudah ada di kode.
- Gap tanpa tiket: auth antar-service + bundle public + kunci bundle bukan HSM (40), Kafka/OpenSearch tanpa TLS/SASL (41), RLS yang dijanjikan ADR-0001 belum ada (42), bypass AI gateway (43), memory poisoning ASI06 (44), abuse unmask (45).
