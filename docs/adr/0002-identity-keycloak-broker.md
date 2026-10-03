# ADR-0002: Identitas admin lewat Keycloak sebagai broker

Status: accepted
Tanggal: 2026-10-03
Tiket: `.scratch/ai-data-security/issues/06-identity-sso-oidc-saml-scim-rbac-abac.md`
Spec: §2, §10.1 (AuthN, AuthZ), §12.1

## Konteks
Admin API butuh SSO OIDC dan SAML ke IdP bank (Entra ID, ADFS, Okta, atau Keycloak yang sudah ada), MFA wajib untuk admin, break-glass yang diaudit, dan re-auth untuk permission sensitif. Opsi lain adalah control-plane menjadi OIDC RP dan SAML SP sendiri. Itu berarti kita memelihara parsing XML signature SAML, session, dan MFA sendiri: kode keamanan kritis yang harus di-pentest dan di-patch terus.

## Keputusan
**Keycloak (Apache-2.0) on-prem sebagai identity broker.**
- Keycloak mem-federasi IdP bank (OIDC atau SAML), menegakkan MFA untuk realm admin, dan menyimpan akun break-glass lokal (WebAuthn/OTP, tanpa ketergantungan ke IdP bank).
- Aplikasi kita hanya menerima **access token OIDC dari Keycloak** dan memvalidasinya sendiri: `iss`, `aud`, `exp`, tanda tangan via JWKS, `acr` untuk MFA, `auth_time` untuk re-auth (step-up, RFC 9470). Tidak ada SAML di kode kita.
- **Otorisasi tetap di aplikasi**, bukan di Keycloak: user dan grup datang lewat **SCIM 2.0** (IdP bank → control-plane), role diikat ke grup atau user di control-plane, dan setiap perubahan tercatat di audit log (ADR tiket 07). Token hanya membawa identitas.
- Break-glass dikenali dari `sub` yang terdaftar di konfigurasi; setiap request-nya dicatat di audit log dan memicu alert.

Ditolak:
- **Native di Go (go-oidc + crewjam/saml).** Tidak menambah komponen, tetapi memindahkan SAML/XML-DSig, session, dan MFA ke kode kita.
- **Role dari claim token Keycloak.** Lebih sedikit kode, tetapi perubahan role terjadi di luar audit log kita dan tidak bisa diberi batas waktu per binding.

## Konsekuensi
- Komponen baru untuk dioperasikan tim platform: Keycloak HA (2 replika) di atas PostgreSQL yang sama standarnya (Patroni). Ini menambah daftar OSS §12.1 dari ADR-0001.
- Keycloak realm, client, LoA/ACR untuk MFA, dan akun break-glass dikonfigurasi sebagai kode (realm export) bersama tim IAM bank.
- SCIM dari IdP bank harus menunjuk ke control-plane, bukan ke Keycloak.
