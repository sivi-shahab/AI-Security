# 28: MCP Gateway core: authz, token exchange, inspeksi

Status: needs-triage
Type: task
Priority: P1
Milestone: M3
Blocked by: 27, 08, 11
Spec: `../spec.md` §4.8 FR-AGT-3..5, FR-AGT-8; §7.2; §8.6

## Konteks
PEP untuk agent → tool.

## Scope
- Proxy MCP Streamable HTTP.
- Validasi token sesuai spec MCP 2026-07-28: OAuth 2.1, RFC 9728, RFC 8707 `resource`, audience.
- Tanpa token passthrough: token exchange RFC 8693 ke kredensial downstream TTL ≤ 15 menit.
- Consent per-client (anti confused deputy).
- DLP + injection scan pada tool-call args, tool results, dan resource reads.
- Allow-list tool + constraint parameter + rate limit + batas kedalaman rantai agent.
- Session audit `prompt → tool_call → result` dengan `trace_id`.

## Acceptance criteria
- [ ] Test: token dengan audience salah ditolak.
- [ ] Test: token upstream tidak pernah muncul di request downstream.
- [ ] Test: indirect injection di tool result terdeteksi dan diblok/di-redact sesuai policy.
- [ ] Suite AgentDojo-style: ASR turun ≥ 70% vs baseline.
