# 23: Web proxy adapter (ICAP REQMOD/RESPMOD)

Status: deferred
Type: task
Priority: P1
Milestone: M3+
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

## Catatan ADR-0001
Ditunda ke M3+ (DEC-5). Dievaluasi ulang setelah [ASM-5] inventaris SWG/CASB/DLP terverifikasi: lanjut bila vendor tidak punya kapabilitas ini, dibatalkan bila sudah ada (event vendor dikonsumsi lewat tiket 15).
