# 10: Detection L2: prompt-injection & jailbreak classifier v1

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 04, 08
Spec: `../spec.md` §4.5 FR-PSEC-1..6, FR-PSEC-10; §9.2; §9.4

## Konteks
Deteksi serangan LLM di luar kemampuan regex.

## Scope
- Classifier biner + multi-label jenis serangan (direct, indirect, role confusion, exfil markdown, suffix).
- Fitur perplexity untuk adversarial suffix.
- Input dengan label `trust=untrusted` diperlakukan terpisah.
- Deteksi role marker palsu dan link/gambar markdown ke domain eksternal (rule L1 pendamping).
- Output `injection_score`, `attack_type[]`, evidence redacted.

## Acceptance criteria
- [ ] FPR benign ≤ 1% pada corpus benign.
- [ ] Detection rate per teknik dilaporkan (encoding, multilingual, indirect, suffix).
- [ ] Kalibrasi ECE ≤ 0,05.
