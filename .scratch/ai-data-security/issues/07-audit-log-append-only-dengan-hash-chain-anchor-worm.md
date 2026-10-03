# 07: Audit log append-only dengan hash chain & anchor WORM

Status: needs-gitlab-run
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
- [x] Test: mengubah satu entri membuat verifikasi gagal di posisi yang tepat. *(Unit: edit isi → seq itu; edit + rehash → seq berikutnya; hapus → seq yang hilang. Integrasi Postgres: bypass trigger, ubah seq 3 → gagal di 3.)*
- [x] Test: anchor harian cocok dengan hash terakhir hari itu.
- [x] Retensi ≥ 5 tahun terkonfigurasi. *(Object lock COMPLIANCE sampai akhir hari + `AUDIT_RETENTION_YEARS` tahun kalender, minimum 5 ditolak di bawahnya; tabel tidak bisa UPDATE/DELETE/TRUNCATE.)*

## Keputusan
- Modul `internal/audit` di control-plane (DEC-3), schema Postgres `audit`, satu rantai global; append diserialisasi dengan advisory lock, `seq` tanpa celah, `ts` dari `clock_timestamp()` DB setelah lock.
- `canonical_json` = JSON dengan key terurut, tanpa HTML escaping, `ts` UTC RFC 3339 µs; `target` dinormalisasi ke bentuk decode JSON sebelum di-hash (sama dengan yang dibaca dari jsonb).
- Anchor = kepala rantai di akhir hari WIB (juga untuk hari tanpa entri), ECDSA P-256 lewat `crypto.Signer` (file key sekarang, PKCS#11/HSM nanti), disimpan `audit-anchors/YYYY-MM-DD.json`. Anchor yang sudah ada tidak bisa diganti dengan head berbeda.
- Verifikasi via CLI `control-plane audit verify --from D --to D` (rantai + anchor setiap hari yang sudah selesai; anchor hilang = gagal). Endpoint HTTP menunggu authn/authz (ticket 06).
- CronJob `audit-anchor` 00:15 WIB; alert `AuditAnchorMissing` bila >26 jam tanpa sukses.

## Hasil verifikasi lokal (2026-10-03)
- Unit + integrasi (Postgres 17, MinIO object lock) lulus dengan `-race`; golangci-lint, trivy config, gitleaks bersih.
- Integrasi: UPDATE/DELETE/TRUNCATE ditolak; anchor = entri terakhir hari itu; retensi < 5 tahun ditolak; objek terkunci tidak bisa dihapus; penghapusan entri ekor hanya terdeteksi lewat anchor (gagal di seq 5).
- CLI e2e: verify gagal sebelum ada anchor, anchor hari berjalan ditolak, anchor ulang idempoten, verify lulus.

## Sisa / follow-up
- Belum ada pemanggil `Append`: event audit (perubahan policy, unmask, kill switch, detokenisasi) ditambahkan di ticket masing-masing (12, 24, 30).
- RLS `tenant_id` belum diterapkan di tabel ini (rantai global); putuskan bersama ticket 06.
- Signer HSM/PKCS#11; Secret `audit-anchor`, `audit-anchor-key`, dan bucket dengan object lock di-provision di luar git.
- Superuser Postgres tetap bisa menonaktifkan trigger; yang menangkapnya adalah anchor WORM.
