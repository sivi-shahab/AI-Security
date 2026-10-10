# 47: Optimasi PDP: OPA eval p99 dan throughput gateway per pod

Status: needs-triage
Type: task
Priority: P1
Milestone: M1
Blocked by: -
Spec: `../spec.md` §13.1 (OPA eval p99 ≤ 5 ms; throughput gateway per pod 4 vCPU ≥ 300 RPS); temuan tiket 21 (`docs/nfr/m1-report.md`)

## Konteks
Hasil tiket 21 (bundle bawaan, input khas gateway):
- `opa bench` di 1 vCPU: median 3,2 ms, p95 7,8 ms, **p99 9,0 ms** (target 5 ms).
- Satu pod (gateway 3 vCPU + OPA 1 vCPU) sehat sampai 60 RPS; di 80 RPS p99 171 ms, di 100 RPS runtuh (503 karena PDP timeout). OPA di 100% CPU, gateway baru ~60%. Dengan OPA 3 vCPU + gateway 1 vCPU, pod sehat di 100 RPS dan mentok di ~225 RPS dengan latensi > 1 detik. **Target 300 RPS tidak tercapai.**
- Profil teratas: `decision.rego:27` (`json.match_schema` atas input di setiap keputusan), lalu pencocokan rule `decision.rego:62-64`, lalu `risk.rego:58`. Setiap request gateway butuh 2 keputusan (request dan response).

## Scope
- Validasi skema input di PEP (Go, sekali) atau skema yang dikompilasi sekali, bukan `json.match_schema` per keputusan. PDP tetap fail closed untuk input yang tidak valid.
- Indeks rule berdasarkan `channel`/`direction`, atau pre-filter, agar tidak semua rule dievaluasi.
- Pertimbangkan satu keputusan untuk response yang bersih (tanpa temuan) bila policy mengizinkan.
- Ukur ulang dengan `deploy/nfr/opa-bench.sh` dan `deploy/nfr/measure.sh` (ramp). Tetapkan pembagian vCPU sidecar/gateway di manifest sesuai hasil.

## Acceptance criteria
- [ ] `opa bench` p99 ≤ 5 ms pada 1 vCPU.
- [ ] Satu pod 4 vCPU ≥ 300 RPS teks dengan overhead p95 ≤ 80 ms dan p99 ≤ 200 ms.
