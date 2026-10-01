# 13: AI Gateway core: provider adapters, redact/block, key vault

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 08, 11
Spec: `../spec.md` §4.6; §5.4; §7.1; §8.7; §10.1 Secrets

## Konteks
PEP P0 untuk app-to-LLM.

## Scope
- Endpoint kompatibel: `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/messages`, `:generateContent`, dan passthrough self-hosted.
- AuthN app via gateway key; provider key diambil dari vault dan tidak pernah dikirim ke klien.
- Alur: normalize → scan → OPA → allow/warn/redact/block; redaction menjaga JSON dan `messages[]` tetap valid.
- Block memakai HTTP 403 dengan body berformat error provider + header `X-AISec-Decision-Id`, `X-AISec-Action`.
- Rate limit dan kuota token per app/user (FR-PSEC-9) via Redis.
- Konfigurasi fail mode per app (§13.3).
- Input `destination.hosting_region` dan `destination.ojk_approval_ref` dari katalog (tiket 16) dikirim ke OPA untuk residency policy (ADR-0001).

## Acceptance criteria
- [ ] Contract test golden request/response per provider.
- [ ] Overhead p95 ≤ 80 ms, p99 ≤ 200 ms (text ≤ 8K token) pada load test.
- [ ] SDK resmi OpenAI/Anthropic tidak crash saat menerima block.
- [ ] Chaos test: detection/OPA mati → perilaku sesuai fail mode.
- [ ] Prompt `restricted` ke provider offshore di-block; `confidential` ter-redact sebelum keluar.

## Out of scope
Response streaming (tiket 14) dan tokenize (tiket 24).
