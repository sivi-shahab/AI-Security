# 06: Identity: SSO OIDC/SAML, SCIM, RBAC/ABAC

Status: needs-triage
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
- [ ] Test matriks role × endpoint (deny by default).
- [ ] Setiap perubahan role tercatat di audit log (tiket 07).
