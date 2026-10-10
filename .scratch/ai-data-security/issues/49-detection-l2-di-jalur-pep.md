# 49: Pasang detection-svc (L2) di jalur PEP dengan timeout dan fallback L1

Status: needs-triage
Type: task
Priority: P1
Milestone: M1
Blocked by: 09, 10
Spec: `../spec.md` §5.2; §9.2; §13.3 (detection timeout default 150 ms → hasil L1 saja); temuan tiket 21 (`docs/nfr/m1-report.md`)

## Konteks
Chaos tiket 21: mematikan detection-svc tidak berpengaruh apa pun pada AI gateway (p95 24 ms, 100% 200). Penyebabnya, gateway (dan MCP gateway) menjalankan L1 in-process lewat `internal/inspect` dan tidak memanggil detection-svc sama sekali. Akibatnya model L2 tiket 09/10 (NER, injection classifier, shadow mode) tidak pernah melihat trafik PEP, timeout 150 ms §13.3 tidak pernah teruji, dan shadow mode tidak menghasilkan data untuk gate rilis §9.4.

## Scope
- PEP memanggil `POST /scan/text` detection-svc (mTLS, tiket 40) dengan batas waktu 150 ms; saat lewat atau gagal, hasil L1 in-process tetap berlaku dan `detection_fallback_total` naik.
- Hitung overhead tambahan terhadap anggaran §13.1 (p95 ≤ 80 ms) dengan `deploy/nfr/measure.sh` setelah model L2 di-mount.
- Laporan shadow L2 masuk decision event (untuk gate §9.4).

## Acceptance criteria
- [ ] Trafik gateway menghasilkan skor L2 (shadow) di decision event.
- [ ] detection-svc mati/lambat: gateway tetap dalam anggaran latensi dan memakai L1 (test chaos).
