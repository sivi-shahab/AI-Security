# 37: Similarity & fingerprint dokumen rahasia

Status: needs-triage
Type: task
Priority: P2
Milestone: M4
Blocked by: 08
Spec: `../spec.md` §4.4 Source Code/IP; §9.1 L3; §9.2

## Konteks
Mendeteksi kebocoran IP/dokumen rahasia yang tidak berpola.

## Scope
- Registrasi corpus rahasia; MinHash/SimHash near-dup + sentence embedding.
- Jalur async untuk file dan opsional inline untuk teks pendek.

## Acceptance criteria
- [ ] Precision/recall pada eval set dokumen rahasia sintetis.
- [ ] Inline tetap dalam budget latensi.
