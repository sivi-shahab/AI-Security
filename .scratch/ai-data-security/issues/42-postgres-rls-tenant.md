# 42: RLS PostgreSQL per tenant (ADR-0001 U11)

Status: needs-triage
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
- [ ] Keputusan tercatat (ADR baru atau amandemen U11).
- [ ] Bila RLS: test isolasi untuk setiap schema yang punya `tenant_id`.
