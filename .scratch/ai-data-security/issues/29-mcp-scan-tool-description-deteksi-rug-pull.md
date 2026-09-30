# 29: MCP: scan tool description & deteksi rug-pull

Status: needs-triage
Type: task
Priority: P1
Milestone: M3
Blocked by: 28
Spec: `../spec.md` §4.8 FR-AGT-3 (tool poisoning); §15 Adversarial

## Konteks
Tool poisoning lewat deskripsi tool atau perubahan diam-diam setelah disetujui.

## Scope
- Scan deskripsi, metadata, dan schema tool saat registrasi (detektor injection + rule).
- Pin hash deskripsi; perubahan memicu status `under_review` dan re-approval.
- Laporan tool berisiko per MCP server.

## Acceptance criteria
- [ ] Test dengan sampel ala MCPTox.
- [ ] Perubahan deskripsi → tool tidak bisa dipanggil sampai di-approve ulang.
