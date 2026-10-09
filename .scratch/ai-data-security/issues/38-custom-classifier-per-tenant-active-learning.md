# 38: Custom classifier per tenant & active learning

Status: needs-gitlab-run
Type: task
Priority: P2
Milestone: M4
Blocked by: 09, 10, 25 (dikerjakan lebih dulu atas permintaan; model untuk 09/10 menyusul)
Spec: `../spec.md` §9.3 isolasi; §9.4

## Konteks
Tuning detektor ke kebutuhan bank tanpa membocorkan data.

## Scope
- Antrean active learning dari feedback triage (redacted).
- Fine-tune per tenant dengan opt-in eksplisit, di dalam tenant boundary.
- Gate rilis model §9.4 + rollout shadow → canary → 100%.

## Acceptance criteria
- [x] Model tenant tidak dapat diakses lintas tenant (test isolasi). *(`TestIsolationAndRollout`, dua tenant dalam satu DB: tenant B tidak melihat event A di antrean, tidak bisa melabeli event A, tidak bisa training dengan label A, tidak melihat dan tidak bisa mempromosikan model A, dan model A tidak berlaku di detection tenant B. Feature hash diberi key pepper tenant: model A di bawah key B kehilangan efeknya (`TestModelGate`).)*
- [x] Tidak ada regresi F1/FPR di atas ambang gate. *(Gate §9.4 dijalankan setiap training terhadap holdout beku per kuartal, dibandingkan dengan model aktif atau detektor apa adanya: F1 tidak boleh turun > 1 poin, FPR tidak boleh naik > 0,2 poin, plus recall ≥ 0,98 (tambahan kami: model tidak boleh menyembunyikan temuan nyata). Data sintetis (kartu test QA di Jira = FP, kartu nasabah di ChatGPT = TP, noise label 3%): FPR 1,00 → 0,13, F1 0,66 → 0,94, recall 1,00. Retrain dari label yang dirusak berstatus `rejected` dan tidak bisa dipromosikan.)*

## Keputusan
- **Model:** model 09/10 belum ada, jadi custom classifier ini adalah logistic regression per tenant di atas detektor L1. Model memprediksi apakah sebuah temuan kelas X itu nyata, dan kelas yang dinilai FP dibuang (`detect.Without`) sebelum ke PDP. Fitur: kata dan bigram snippet ter-redact (disilangkan dengan kelas), channel, arah, app, dan bucket confidence; di-hash HMAC dengan pepper tenant. Threshold konservatif: ≥ 99% TP di data training tetap lolos, maksimal 0,5.
- **Data training hanya yang sudah ada di event:** snippet ter-redact ≤ 200 karakter dan metadata. Tidak ada konten mentah. `detect.Snippet` adalah satu-satunya pembuat snippet, untuk event PEP maupun inferensi (detection-svc kini mengembalikan `snippet`), sehingga tidak ada train/serve skew.
- **Label** (`POST /tuning/labels`, SOC `incident.write`): TP/FP per kelas per event insiden milik tenant. **Antrean active learning** (`GET /tuning/queue`): temuan yang belum dilabel, diurutkan berdasarkan ketidakpastian model live (|p − threshold|), atau jarak confidence detektor dari 0,8 bila belum ada model. Ini juga menyediakan pipeline label TP/FP untuk tiket 25.
- **Opt-in eksplisit** (`PUT /tuning/optin`, DPO `compliance.write`, alasan wajib, append-only). Tanpa opt-in, training ditolak.
- **Training** (`POST /tuning/models`, `policy.write`): minimal 40 label dengan ≥ 5 TP dan FP di train maupun holdout. Split per event memakai HMAC (20% holdout). **Holdout dibekukan per kuartal** saat training pertama di kuartal itu (`tuning.holdout`, append-only). Temuan saat implementasi: tanpa pembekuan, label holdout yang ikut dirusak membuat model rusak lolos gate.
- **Rollout** (`POST /tuning/models/{v}/stage`, `policy.publish`, 4-eyes terhadap trainer): candidate → shadow (hanya skor yang dilaporkan) → canary (5% teks, stabil per teks; sisanya memakai model aktif atau detektor) → active (model aktif lama di-retire). Rollback = retired. Semua langkah diaudit.
- Serving: detection-svc memuat model shadow/canary/active dan me-reload saat stage berubah (≤ 60 detik). Respons memuat `tuning` (versi, stage, skor per kelas, kelas yang ditekan, laporan shadow).

## Hasil verifikasi lokal (2026-10-10)
- `go test -race ./...` dengan Postgres hijau (termasuk `mcpgw` di run ini). `datascan TestScan` sempat gagal acak karena pengecekan kebocoran memakai `LIKE '%4111%'` yang bisa cocok dengan UUID atau hash. Sudah diperbaiki ke nomor kartu lengkap. golangci-lint 0 issue.

## Sisa
- Fine-tune model NER/injection per tenant setelah tiket 09/10 punya model (memakai antrean, opt-in, holdout beku, gate, dan rollout yang sama).
- Eval di data nyata bank; double labeling κ ≥ 0,8 (§9.3) untuk label yang masuk holdout. Pembekuan melindungi kuartal berjalan, tapi bukan label yang sudah salah sebelum dibekukan.
- Dashboard metrik shadow/canary (event menyimpan laporan `tuning` setelah PEP mengisinya).
- Postgres RLS untuk tabel tuning (isolasi saat ini lewat filter `tenant_id` di setiap query, sama seperti modul lain).
