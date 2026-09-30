# 07: Audit log append-only dengan hash chain & anchor WORM

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 05
Spec: `../spec.md` §4.11 FR-COMP-4; §10.2

## Konteks
Auditor butuh jejak audit yang tidak bisa dimodifikasi.

## Scope
- Tabel `audit_log` dengan `hash = SHA-256(prev_hash ‖ canonical_json(entry))`.
- Anchor harian ditandatangani KMS dan disimpan di object storage dengan object lock.
- Endpoint/CLI verifikasi rantai untuk rentang waktu tertentu.

## Acceptance criteria
- [ ] Test: mengubah satu entri membuat verifikasi gagal di posisi yang tepat.
- [ ] Test: anchor harian cocok dengan hash terakhir hari itu.
- [ ] Retensi ≥ 5 tahun terkonfigurasi.
