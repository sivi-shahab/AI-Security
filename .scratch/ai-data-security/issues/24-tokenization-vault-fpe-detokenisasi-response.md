# 24: Tokenization vault (FPE) + detokenisasi response

Status: needs-triage
Type: task
Priority: P1
Milestone: M2
Blocked by: 13
Spec: `../spec.md` §4.6 FR-DLP-3; §7.1

## Konteks
Memungkinkan LLM memproses data tanpa melihat nilai asli.

## Scope
- Vault FPE (FF1) dengan kunci di KMS/HSM; TTL token konfigurabel.
- Aksi `tokenize` di gateway; detokenisasi response hanya untuk principal berhak.
- Audit setiap detokenisasi.

## Acceptance criteria
- [ ] Test round-trip format-preserving untuk NIK, rekening, dan PAN.
- [ ] Principal tanpa hak menerima nilai tertokenisasi.
- [ ] Failover active-passive diuji.
