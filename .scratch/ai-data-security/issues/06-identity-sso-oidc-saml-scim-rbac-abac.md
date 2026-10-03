# 06: Identity: SSO OIDC/SAML, SCIM, RBAC/ABAC

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 05
Spec: `../spec.md` §2; §10.1 AuthN/AuthZ

## Konteks
Admin UI/API butuh identitas dan otorisasi sebelum fitur lain bisa dipakai.

## Scope
- Login OIDC/SAML dengan MFA wajib untuk admin.
- SCIM 2.0 untuk provisioning user/grup.
- Role bawaan sesuai persona §2 + atribut ABAC (unit bisnis, region, sensitivitas).
- Permission sensitif (`evidence.unmask`, `policy.publish`, `agent.kill.global`) butuh re-auth + justifikasi.
- Break-glass account.

## Acceptance criteria
- [x] Test matriks role × endpoint (deny by default). *(`cmd/control-plane/routes_test.go`: setiap route terdaftar × 12 role + user tanpa binding + tanpa token, lewat tabel route produksi; permukaan publik dipin; route tanpa permission tidak bisa didaftarkan.)*
- [x] Setiap perubahan role tercatat di audit log (tiket 07). *(Bind/unbind, membership grup SCIM (added/removed), aktivasi/deaktivasi user, create/delete user dan grup, dalam transaksi yang sama dengan perubahannya.)*

## Keputusan
- **ADR-0002**: Keycloak sebagai broker ke IdP bank (OIDC/SAML), MFA, dan break-glass. Kode kita hanya memvalidasi access token Keycloak (JWKS, `iss`, `aud`, `exp`, `typ=Bearer`, `acr` untuk MFA, `auth_time` untuk step-up).
- Otorisasi di aplikasi: user/grup dari SCIM 2.0 (`/scim/v2/Users|Groups`, token sendiri, subset yang dipakai Entra/Okta), role diikat ke user atau grup di `identity.role_bindings`, dengan atribut ABAC (unit bisnis, region, clearance sensitivitas) dan masa berlaku (auditor time-boxed). Token `preferred_username` = SCIM `userName` (case-insensitive). User nonaktif atau tidak dikenal tidak punya permission.
- Role bawaan = persona §2, ditambah `policy_approver` (4-eyes: tidak ada role yang bisa menulis dan mem-publish policy sekaligus, dites) dan `break_glass`.
- Permission sensitif (`evidence.unmask`, `policy.publish`, `agent.kill.global`, `identity.admin`): login ≤ 5 menit (step-up, `WWW-Authenticate: insufficient_user_authentication`), justifikasi ≥ 10 karakter, setiap percobaan (diterima/ditolak) diaudit; tanpa audit, tanpa akses.
- Break-glass: `sub` dari konfigurasi, setiap request diaudit, metrik `breakglass_requests_total` + alert critical. Break-glass tidak bisa unmask evidence atau publish policy (untuk menjaga platform tetap jalan, bukan akses data).
- Raw evidence pindah ke `GET /incidents/{id}/evidence/{eid}/raw` (permission per route); `AUTH_MODE=trusted-proxy` dari ticket 18 dihapus.

## Hasil verifikasi lokal (2026-10-03)
- Unit (authz, matriks route), integrasi Postgres (SCIM + binding + audit, incident API dengan auth baru), seluruh suite dengan `-race`; golangci-lint, trivy config bersih.
- Keycloak 26.4 nyata: login authorization-code menghasilkan access token dengan `typ=Bearer`, `aud` dari audience mapper, `acr`, `auth_time`; verifier menerima token itu, menolak ID token, token yang diubah, dan audience lain. Password grant tidak membawa `auth_time` (verifier fail closed: step-up selalu ditolak).

## Sisa / follow-up
- Realm Keycloak sebagai kode bersama tim IAM: federasi IdP bank, OTP/WebAuthn untuk admin, mapping ACR → LoA (nilai untuk `OIDC_MFA_ACR`), audience mapper, akun break-glass.
- ABAC baru dipakai lewat `Caller.Can(perm, Resource{...})`; resource yang membawa unit bisnis/region/sensitivitas (aplikasi, agent, incident) memakainya saat field tersebut ada (ticket 13, 16, 27).
- SCIM: pagination (`startIndex`/`count`), filter selain `eq`, dan ETag belum ada; cukup untuk Entra/Okta provisioning dasar.
- Service identity (SPIFFE/mTLS) untuk sidecar/PEP: di luar tiket ini.
