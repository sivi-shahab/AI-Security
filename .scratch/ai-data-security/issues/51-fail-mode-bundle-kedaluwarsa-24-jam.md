# 51: Fail mode saat bundle policy kedaluwarsa > 24 jam

Status: needs-triage
Type: task
Priority: P2
Milestone: M2
Blocked by: -
Spec: `../spec.md` §13.3 ("Jika bundle kedaluwarsa > 24 jam, PEP masuk mode fail-mode policy"); temuan tiket 21 (`docs/nfr/m1-report.md`)

## Konteks
Chaos tiket 21 membuktikan bagian pertama §13.3: OPA yang di-restart saat Policy Service mati melayani lagi dalam 1 detik dari bundle tersimpan (`persist: true`). Bagian kedua belum ada. Tidak ada kode PEP (`internal/aigw`, `internal/mcpgw`) maupun konfigurasi OPA yang memeriksa umur bundle aktif, sehingga PEP bisa terus menegakkan policy lama tanpa batas waktu saat Policy Service tidak bisa dijangkau.

## Scope
- PEP membaca umur aktivasi bundle terakhir (OPA status API `/health?bundles` atau `/v1/status` → `last_successful_activation`, atau metrik `bundle_loaded_timestamp`). Lebih dari 24 jam berarti diperlakukan seperti PDP tidak tersedia (`fail_closed`/`fail_open` per app) plus metrik dan alert `policy_bundle_stale`.
- Alert lebih awal (mis. > 1 jam tanpa aktivasi baru) di `deploy/cluster/alerts.yaml`.

## Acceptance criteria
- [ ] Test: bundle yang aktivasi terakhirnya > 24 jam membuat app `fail_closed` menolak dan app `fail_open` meneruskan dengan `fail_open_total`.
- [ ] Alert bundle basi dengan test metrik.
