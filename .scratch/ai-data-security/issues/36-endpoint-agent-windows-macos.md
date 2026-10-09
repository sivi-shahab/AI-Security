# 36: Endpoint agent (Windows/macOS)

Status: deferred
Type: task
Priority: P2
Milestone: M4 (M3+ re-eval)
Blocked by: 08, 11, 35 (rilis produksi; DPIA harus di-review ulang untuk clipboard dan app desktop)
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

## Catatan ADR-0001
Ditunda ke M3+ (DEC-5). Dievaluasi ulang setelah [ASM-5] inventaris SWG/CASB/DLP terverifikasi: lanjut bila vendor tidak punya kapabilitas ini, dibatalkan bila sudah ada (event vendor dikonsumsi lewat tiket 15).
