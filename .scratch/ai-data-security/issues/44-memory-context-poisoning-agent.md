# 44: Inspeksi tulis ke memory agent / vector store (FR-AGT-9)

Status: needs-triage
Type: task
Priority: P1
Milestone: M2
Blocked by: 28
Spec: `../spec.md` §4.8 FR-AGT-9; OWASP ASI06, LLM08; `docs/threat-model.md` G5

## Konteks
Threat model (tiket 02) G5: belum ada kontrol untuk ASI06 (memory & context poisoning). Konten berinjeksi yang tersimpan di memory jangka panjang atau vector store akan dibaca ulang oleh agent sebagai konteks tepercaya.

## Scope
- MCP gateway mengenali tool tulis memory/vector store (ditandai di registry tool, misalnya `writes_memory: true`) dan menginspeksi argumennya dengan detektor injection + DLP sebelum diteruskan.
- Provenance: sumber tulis (agent, trace, asal konten: user/tool result/web) dicatat di decision event.
- Konten dari sesi yang ter-taint injection tidak boleh ditulis ke memory tanpa approval.

## Acceptance criteria
- [ ] Tulis memory berisi injection diblok atau butuh approval (test gateway).
- [ ] Event tulis memory membawa provenance.
- [ ] Skenario poisoning sintetis (tulis → baca ulang di sesi lain) tertangkap.
