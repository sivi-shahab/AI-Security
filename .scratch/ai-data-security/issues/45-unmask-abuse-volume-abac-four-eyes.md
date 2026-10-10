# 45: Kontrol abuse unmask evidence: alert volume, ABAC, four-eyes

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 18
Spec: `../spec.md` §10.1 AuthZ (ABAC); FR-INC-4; `docs/threat-model.md` §4.5, G6

## Konteks
Threat model (tiket 02) G6: unmask sudah butuh permission, step-up, justifikasi, dan diaudit. Namun belum ada deteksi volume/pola per analis, pemeriksaan memakai `authz.Resource{}` kosong (ABAC unit/region tidak membatasi), dan tidak ada four-eyes untuk evidence `restricted`.

## Scope
- Alert bila unmask per analis melewati ambang per hari, atau menyasar principal yang sama berulang kali.
- ABAC: atribut unit bisnis/region insiden dibandingkan dengan atribut analis.
- Evidence `restricted`: unmask butuh persetujuan analis kedua.

## Acceptance criteria
- [x] Analis di luar unit/region insiden ditolak (test), dan penolakan diaudit. *(`TestUnmaskABACAndFourEyes`: DPO dengan binding `business_units: [treasury]` ditolak 403 untuk insiden `bu:retail`/`region:jakarta`, sedangkan DPO retail berhasil. DPO dengan clearance `confidential` ditolak untuk insiden `restricted`. Setiap penolakan tercatat `evidence.unmask.denied` (atau `.request.denied` / `.approve.denied`) beserta alasannya.)*
- [x] Alert volume unmask di `deploy/cluster/alerts.yaml` dengan test metrik. *(`UnmaskVolumeHigh` (> 20 unmask per analis dalam 24 jam) dan `UnmaskSamePrincipalRepeated` (≥ 5 unmask tentang principal yang sama dalam 24 jam), dari gauge `evidence_unmasks_24h{analyst}` dan `evidence_unmask_same_principal_24h{analyst}` di `/metrics` control-plane. `TestUnmaskVolumeMetric`: 8 unmask, 6 di antaranya tentang orang yang sama, menghasilkan gauge 8 / 6. Unmask yang ditolak tidak dihitung. Test juga memastikan expr alert membaca gauge tersebut. Diuji juga dengan `promtool test rules` (lokal, lihat di bawah).)*
- [x] Unmask evidence `restricted` tanpa approver kedua ditolak. *(Ditolak tanpa request yang disetujui. Requester tidak bisa menyetujui request sendiri. Approver di luar unit ditolak. Approval yang sudah dipakai, approval milik orang lain, dan approval yang lewat 1 jam tidak berlaku. Unmask yang diberikan mencatat `request` dan `approver` di audit.)*

## Keputusan
- **Atribut ABAC insiden:** unit bisnis dan region diambil dari grup IdP principal yang ikut di event, dengan konvensi `bu:<unit>` dan `region:<region>` (dipetakan admin IdP/SCIM). Nilai pertama yang terlihat dipakai untuk insiden. Sensitivitas insiden = konten paling sensitif di antara event-nya. Insiden tanpa grup `bu:`/`region:` tidak dibatasi pada atribut itu, sesuai semantik `authz.Attrs.Covers` (atribut kosong di resource = tidak berlaku). Alasannya: principal di event berupa HMAC, dan tidak ada direktori lain di platform yang memetakan principal ke unit.
- **Pemeriksaan:** `Unmask`, `RequestUnmask`, dan `ApproveUnmask` memakai satu fungsi `mayUnmask`: permission, lalu ABAC terhadap `authz.Resource{BusinessUnit, Region, Sensitivity}` insiden (clearance binding juga berlaku), lalu justifikasi. Router tetap memeriksa permission dan step-up dengan resource kosong. Pemeriksaan resource dilakukan di store, karena insiden baru diketahui di sana.
- **Four-eyes `restricted`** (`POST /incidents/{id}/evidence/{eid}/unmask-requests`, lalu `POST /incidents/{id}/unmask-requests/{rid}/approve`, keduanya `evidence.unmask` dengan step-up dan justifikasi): satu approval berlaku untuk satu unmask oleh requester, maksimal 1 jam. Approval dikonsumsi di transaksi yang sama dengan audit grant. "Restricted" ditentukan per insiden, karena evidence mentah tidak punya label sensitivitas sendiri.
- **Metrik volume:** dihitung dari audit log (`evidence.unmask` yang diberikan, 24 jam), digabung dengan principal di event insiden. Ambang ada di rule alert, bukan di kode.
- `authz.sensitivityOrder` diekspor menjadi `authz.Sensitivities` (dipakai juga oleh query sensitivitas insiden).

## Hasil verifikasi lokal (2026-10-10)
- `go vet ./...` bersih. golangci-lint v2.5.0: 0 issue. `go test -race ./...` dengan Postgres 17: semua paket hijau kecuali `mcpgw TestKillSwitch`. Test itu gagal karena timing (sesi terputus dalam 4,9 detik, batas test 2 detik) saat load average host ~54 (beberapa worker paralel); paket `mcpgw` tidak tersentuh tiket ini. `policysvc` sempat timeout di run penuh, tapi lulus saat diulang sendiri.
- `promtool test rules` (prom/prometheus v3.5.0) untuk kedua alert, dengan salinan rule dalam format plain: SUCCESS. CI belum menjalankan promtool.

## Sisa
- Konvensi grup `bu:`/`region:` harus disepakati dengan tim IdP. Tanpa grup itu, ABAC tidak membatasi insiden.
- Label sensitivitas per evidence (bukan per insiden) bila nanti forensic capture menyimpan beberapa jenis konten.
- Notifikasi ke calon approver (chat/email) untuk request four-eyes. Sementara ini request terlihat di detail insiden (`unmask_requests`).
- Ulang `mcpgw TestKillSwitch` di CI (runner tanpa beban paralel).
