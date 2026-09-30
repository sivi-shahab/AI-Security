# 23: Web proxy adapter (ICAP REQMOD/RESPMOD)

Status: needs-triage
Type: task
Priority: P1
Milestone: M2
Blocked by: 01, 08, 11
Spec: `../spec.md` §5.4; §11; §17 risiko TLS

## Konteks
Coverage inline tanpa extension, memakai SWG yang sudah ada (bergantung keputusan tiket 01).

## Scope
- Adapter ICAP untuk request dan response ke domain AI.
- Parsing payload API/web GenAI umum.
- Kebijakan blok QUIC/HTTP3 ke domain AI.
- Konteks device/network dari SWG.

## Acceptance criteria
- [ ] Test dengan SWG target bank.
- [ ] Overhead sesuai budget §13.1.
- [ ] Fail mode terkonfigurasi.
