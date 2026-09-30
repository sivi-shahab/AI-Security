# 36: Endpoint agent (Windows/macOS)

Status: needs-triage
Type: task
Priority: P2
Milestone: M4
Blocked by: 08, 11
Spec: `../spec.md` §3.1 P2; §5.4

## Konteks
Coverage off-network, aplikasi AI desktop, clipboard, dan agent lokal.

## Scope
- Agent ringan: deteksi AI desktop app dan agent lokal (termasuk MCP STDIO wrapper), clipboard ke app AI, file ke app AI.
- Policy dari bundle OPA yang sama.
- Integrasi konteks EDR.

## Acceptance criteria
- [ ] Matriks kompatibilitas OS lulus.
- [ ] Overhead CPU/memori dalam batas yang disepakati (`unspecified`, tetapkan di awal tiket).
