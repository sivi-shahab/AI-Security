# 16: AI app catalog & status sanction

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 03, 15
Spec: `../spec.md` §4.1 FR-DISC-1..5; §8.4

## Konteks
Katalog dipakai sebagai input `destination` di policy dan untuk laporan shadow AI.

## Scope
- Model data `AI_APP` + `AI_APP_FINGERPRINT` (§6).
- Status `sanctioned | tolerated | unsanctioned | blocked | under_review` beserta owner, alasan, dan `review_at`.
- Feed katalog berversi + override lokal tanpa redeploy; feed ditandatangani.
- API `GET/PATCH /apps` dan agregasi `APP_USAGE_DAILY`.
- Atribut risiko: `trains_on_data`, retensi, `hosting_region`, sertifikasi.

## Acceptance criteria
- [ ] Perubahan status tercatat di audit log.
- [ ] Perubahan status ter-reflect di keputusan OPA ≤ 60 s.
- [ ] Feed tanpa signature valid ditolak.
