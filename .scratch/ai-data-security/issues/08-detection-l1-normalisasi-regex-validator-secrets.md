# 08: Detection L1: normalisasi + regex + validator + secrets

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 04, 05
Spec: `../spec.md` §4.4 FR-CLS-1..4; §4.5 FR-PSEC-3; §9.1

## Konteks
Fast path deterministik dengan budget ≤ 10 ms. Semua PEP bergantung padanya.

## Scope
- Normalizer: NFKC, strip zero-width & tag Unicode, homoglyph map, decode berlapis (base64/hex/URL/ROT13) dengan depth ≤ 3.
- Validator: NIK (struktur wilayah + tanggal lahir, perempuan +40), KK, NPWP 15/16 digit, No. HP +62/08, PAN (Luhn + BIN), rekening (format bank).
- Secret detection: pola API key vendor, PEM, JWT, connection string + entropy.
- Output per match: `{type, confidence, span_offsets, validator_passed, context_score}` + agregasi sensitivity (FR-CLS-3).
- Endpoint `POST /scan/text` (tanpa policy dulu).

## Acceptance criteria
- [ ] Precision ≥ 0,95 dan recall ≥ 0,90 pada kelas P0 di eval set v1 (tiket 04).
- [ ] p95 ≤ 10 ms untuk teks 8K token.
- [ ] Test untuk tiap validator: kasus valid, invalid, dan tepi.
- [ ] Fuzz test normalizer/decoder.
