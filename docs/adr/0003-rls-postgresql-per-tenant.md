# ADR-0003: RLS PostgreSQL per tenant, dan cakupannya

Status: accepted (mengamandemen ADR-0001 U11)
Tanggal: 2026-10-10
Tiket: `.scratch/ai-data-security/issues/42-postgres-rls-tenant.md`
Spec: §10.1 Tenant isolation; threat model G3

## Konteks
ADR-0001 U11 menetapkan "`tenant_id` + RLS PostgreSQL di semua tabel" sebagai defense-in-depth. Kenyataannya per 2026-10-10:
- 11 tabel punya kolom `tenant_id`: `incident.incidents`, `incident.blocks`, `riskcal.versions`, `similarity.docs`, `tokvault.keys`, `tokvault.tokens`, empat tabel `tuning.*`, dan `audit.audit_log`.
- 6 tabel adalah anak `incident.incidents` lewat `incident_id`.
- Sekitar 30 tabel lain tidak punya `tenant_id`. Isinya konfigurasi dan inventaris satu deployment: katalog app, policy dan release, registry agent, identitas/SCIM, compliance, inventaris data-at-rest.
- Belum ada satu pun policy RLS. Isolasi hanya bergantung pada filter `tenant_id` di setiap query.

Setiap proses melayani satu tenant (`TENANT_ID`), dan satu deployment = satu bank = satu database.

## Keputusan
1. **RLS diterapkan pada data yang memang per tenant.** Setiap tabel dengan `tenant_id` diberi policy `tenant` dengan kondisi `tenant_id = current_setting('app.tenant_id', true)::uuid` untuk baca dan tulis (USING + WITH CHECK). Tabel anak tanpa `tenant_id` ikut tenant induknya (`incident_id IN (SELECT id FROM incident.incidents)`; subquery itu sendiri tunduk pada policy induk). Semuanya `ENABLE` + `FORCE ROW LEVEL SECURITY`, jadi pemilik tabel (role aplikasi yang menjalankan schema) juga terikat. Diterapkan oleh `tenantdb.Isolate`/`IsolateChild` di `Open` tiap modul secara idempoten.
2. **Tenant dipatok per koneksi, di satu tempat.** `tenantdb.Pool` mengirim `app.tenant_id` sebagai startup parameter di setiap koneksi pool. Tidak ada jalur query yang bisa lupa menyetelnya, termasuk worker dan consumer. Tanpa setelan, `current_setting(…, true)` bernilai NULL dan tidak ada baris yang cocok (fail closed). Pool menolak role superuser atau `BYPASSRLS`, kecuali `DATABASE_ALLOW_BYPASSRLS=true` untuk development lokal. Consumer event membuang event tenant lain (`events.OnlyTenant`) sebelum handler, supaya satu record palsu tidak menghentikan consumer.
3. **Tabel tanpa `tenant_id` tidak diberi kolom baru.** Batas tenant untuk data konfigurasi deployment adalah database. U11 diamandemen: "RLS di semua tabel yang menyimpan data per tenant; data konfigurasi deployment diisolasi per database".
4. **`audit.audit_log` di luar RLS.** Log ini satu hash chain lintas tenant: verifikasi chain, anchor WORM, dan tail SIEM membaca semuanya berurutan. Policy per tenant akan memutus chain bagi pembaca mana pun. Perlindungannya tetap: trigger append-only, anchor WORM, dan baca hanya lewat `audit.read`.

Ditolak:
- **Menambah `tenant_id` ke ~30 tabel konfigurasi.** Diff besar di semua store tanpa manfaat selama satu database = satu bank. Kalau grup/anak usaha ikut, database terpisah per entitas lebih sederhana dan lebih kuat daripada RLS di tabel konfigurasi.
- **`SET LOCAL` per transaksi di setiap query.** Butuh perubahan di setiap store dan mudah terlewat. Patok per koneksi setara untuk proses satu tenant.
- **Mengubah ADR menjadi "tanpa RLS".** Kebocoran lintas tenant di data insiden, token vault, dan model tuning berdampak tinggi bila suatu saat database dipakai bersama. Biaya RLS di tabel itu kecil.

## Konsekuensi
- Role aplikasi di produksi: `NOSUPERUSER NOBYPASSRLS`. Test (`internal/tenantdb`) memakai role seperti itu sebagai pemilik tabel.
- Test lain yang terhubung sebagai superuser tetap jalan karena superuser melewati RLS. Pemeriksaan isolasi ada di `TestRowLevelSecurity`, yang juga gagal bila ada tabel ber-`tenant_id` (atau anaknya lewat foreign key) yang belum di-FORCE.
- Pemilik tabel masih bisa menjalankan `ALTER TABLE … NO FORCE ROW LEVEL SECURITY`. Pemisahan role migrasi (pemilik) dan role aplikasi (DML saja) dicatat sebagai sisa.
- Proses yang suatu saat melayani beberapa tenant harus beralih ke `set_config('app.tenant_id', …, true)` per transaksi (ditandai `ponytail:` di `tenantdb.Pool`).

## Pemicu review
- Ada entitas grup/anak usaha yang akan memakai database yang sama (U11): tentukan database per entitas, atau `tenant_id` + RLS di tabel konfigurasi.
- Proses multi-tenant (satu proses, beberapa tenant).
