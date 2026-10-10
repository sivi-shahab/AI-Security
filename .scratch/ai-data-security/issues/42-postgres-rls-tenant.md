# 42: RLS PostgreSQL per tenant (ADR-0001 U11)

Status: needs-gitlab-run
Type: task
Priority: P2
Milestone: M2
Spec: `../spec.md` §10.1 Tenant isolation; `docs/adr/0001-hosting-residency-build-scope.md` U11; `docs/threat-model.md` G3

## Konteks
ADR-0001 U11 menetapkan `tenant_id` + RLS di semua tabel sebagai defense-in-depth. Saat ini belum ada satu pun policy RLS; isolasi bergantung pada filter di setiap query, dan `authz.Caller` tidak membawa tenant.

## Scope
- Putuskan: terapkan RLS (`SET app.tenant_id` per transaksi + policy per tabel), atau ubah ADR bila single-tenant dianggap cukup.
- Bila diterapkan: role DB aplikasi tanpa `BYPASSRLS`; test otomatis bahwa query tanpa konteks tenant tidak mengembalikan baris.

## Acceptance criteria
- [x] Keputusan tercatat (ADR baru atau amandemen U11). *(`docs/adr/0003-rls-postgresql-per-tenant.md`. U11 di ADR-0001 diberi catatan amandemen.)*
- [x] Bila RLS: test isolasi untuk setiap schema yang punya `tenant_id`. *(`internal/tenantdb` `TestRowLevelSecurity`, memakai role aplikasi `NOSUPERUSER NOBYPASSRLS` yang menjadi pemilik tabel. Schema yang diuji: `incident`, `riskcal`, `similarity`, `tokvault`, `tuning`. Struktur: setiap tabel ber-`tenant_id` dan setiap tabel dengan foreign key ke tabel itu wajib RLS + FORCE + policy `tenant` dengan ekspresi yang benar. Tabel baru yang lupa diisolasi membuat test gagal; `audit.audit_log` dikecualikan dengan alasan tertulis. Perilaku, untuk 16 tabel: tanpa tenant 0 baris; sebagai tenant A hanya 1 baris miliknya, tidak ada baris tenant lain; insert/update ke tenant B ditolak "row-level security"; update/delete baris B kena 0 baris; `tenantdb.Pool` menolak superuser kecuali `DATABASE_ALLOW_BYPASSRLS=true`, juga menolak tenant id yang tidak valid.)*

## Keputusan
- **RLS pada data per tenant** (ADR-0003). Ada 10 tabel ber-`tenant_id` (`incident.incidents`, `incident.blocks`, `riskcal.versions`, `similarity.docs`, `tokvault.keys`, `tokvault.tokens`, `tuning.optin/labels/models/holdout`) dengan policy `tenant_id = current_setting('app.tenant_id', true)::uuid` (USING + WITH CHECK). Enam tabel anak insiden (`incident_events`, `evidence`, `transitions`, `actions`, `tickets`, `unmask_requests`) memakai policy lewat induknya. Semuanya `ENABLE` + `FORCE`, dipasang idempoten oleh `tenantdb.Isolate`/`IsolateChild` di `Open` tiap modul. DDL hanya dijalankan bila belum ada, dengan advisory lock untuk replika yang start bersamaan.
- **Tenant dipatok per koneksi** lewat startup parameter `app.tenant_id` di `tenantdb.Pool`, dipakai control-plane, token-vault, connector-worker, dan detection-svc. Satu proses melayani satu tenant (`TENANT_ID`). Tanpa setelan: fail closed (0 baris). Superuser/`BYPASSRLS` ditolak kecuali untuk development. Consumer event di control-plane membuang event tenant lain (`events.OnlyTenant`), karena tanpa itu insert yang ditolak RLS akan menghentikan consumer.
- **Tabel konfigurasi tanpa `tenant_id` (~30) tidak diubah:** batas tenant-nya adalah database (satu deployment = satu bank). Pemicu review: ada anak usaha yang memakai database yang sama.
- **`audit.audit_log` di luar RLS:** satu hash chain lintas tenant yang dibaca utuh oleh verifikasi, anchor WORM, dan tail SIEM. Tetap append-only, dan dibaca lewat `audit.read`.
- siem-export (hanya audit log) dan `audit.Open` tidak diubah.

## Hasil verifikasi lokal (2026-10-10)
- `TestRowLevelSecurity` dan `TestOnlyTenant` hijau. `go vet ./...`: bersih. golangci-lint v2.5.0: 0 issue.
- `go test -race ./...` dengan Postgres 17 + OpenSearch 2.19.3: semua paket hijau kecuali `mcpgw.TestKillSwitch` (timing, sesi terputus 2,9–3,9 detik terhadap batas 2 detik). Test itu tidak memakai database atau paket yang diubah tiket ini, dan host sedang pada load ~16–23 dari pekerjaan paralel. Sama dengan yang dilaporkan di tiket 41, 44, dan 45. Perlu dijalankan di host sepi atau CI.
- Test lain yang terhubung sebagai superuser tetap jalan karena superuser melewati RLS. Di produksi, role aplikasi wajib `NOSUPERUSER NOBYPASSRLS`; `tenantdb.Pool` menolak start bila tidak.

## Sisa
- Pemisahan role pemilik/migrasi (DDL) dan role aplikasi (DML saja). Saat ini aplikasi memiliki tabel, sehingga dengan SQL injection secara teori bisa `ALTER TABLE … NO FORCE ROW LEVEL SECURITY`.
- Provisioning role aplikasi (`NOSUPERUSER NOBYPASSRLS`) di Patroni dicatat di runbook deploy oleh tim platform.
- Bila suatu proses melayani beberapa tenant: `set_config` per transaksi (ditandai `ponytail:` di `tenantdb.Pool`).
