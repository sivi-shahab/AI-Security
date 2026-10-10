# 24: Tokenization vault (FPE) + detokenisasi response

Status: needs-gitlab-run
Type: task
Priority: P1
Milestone: M2
Blocked by: 13
Spec: `../spec.md` §4.6 FR-DLP-3; §7.1

## Konteks
Memungkinkan LLM memproses data tanpa melihat nilai asli.

## Scope
- Vault FPE (FF1) dengan kunci di KMS/HSM; TTL token konfigurabel.
- Aksi `tokenize` di gateway; detokenisasi response hanya untuk principal berhak.
- Audit setiap detokenisasi.

## Acceptance criteria
- [x] Test round-trip format-preserving untuk NIK, rekening, dan PAN. *(`TestRoundTrip` (Postgres): NIK polos dan berspasi, rekening 10/13/15 digit, PAN 16 berspasi dan Amex 15, HP `+62`/`08`, NPWP bertitik. Token sama panjang dan pemisahnya di posisi yang sama; nilai yang sama selalu menghasilkan token yang sama; antar-kelas berbeda; bentuk digit polos dari token juga kembali. `TestFF1Vector` mengunci library ke sampel 1 NIST SP 800-38G.)*
- [x] Principal tanpa hak menerima nilai tertokenisasi. *(`TestTokenize`: provider hanya melihat token; app `detokenize: true` menerima nilai asli di jawaban (lewat vault, diaudit); app tanpa hak menerima token; vault mati → nilai di-redact, tidak pernah terkirim. `TestTokenizeStream`: token yang terpotong antar-delta dikembalikan utuh.)*
- [x] Failover active-passive diuji. *(`TestFailover`: dua replika berbagi Postgres, hanya pemegang advisory lock yang ready dan melayani; replika aktif mati → replika pasif mengambil lock, dan token yang diterbitkan sebelumnya tetap bisa didetokenisasi lewat client yang mencoba URL berikutnya.)*

## Keputusan
- **Service `token-vault`** (`internal/tokvault`, `cmd/token-vault`): FF1 radix 10 (library `capitalone/fpe`, Apache-2.0, dengan vektor NIST), tweak = nama kelas (satu domain per kelas). Kunci FF1 per tenant di-wrap KEK (AES-256-GCM, `internal/seal`, dipakai bersama incident). Pola KEK sama dengan evidence incident: file dari Vault/HSM; panggilan unwrap KMS menyusul bersama §10.1.
- **Tanpa plaintext tersimpan.** Tabel `tokvault.tokens` hanya menyimpan HMAC token + `expires_at`. Token hanya dikembalikan selama terdaftar (TTL per app, default 60 menit, maksimal 7 hari); token kedaluwarsa tetap menjadi token dan dibersihkan berkala. Setiap detokenisasi ditulis ke audit log (app, principal HMAC, trace, kelas, HMAC token) sebelum nilai keluar: tanpa catatan audit, tidak ada nilai.
- **Kelas yang bisa di-tokenize:** NIK, KK, NPWP, HP (prefix `08`/`628` dipertahankan), rekening, PAN. Hanya digit yang dienkripsi; pemisah tetap di tempatnya. Kelas lain di-redact.
- **Gateway:** aksi `tokenize` memakai vault untuk kelas numerik dan mengalahkan redact dari rule yang lebih lemah (FR-POL-4). Token yang diterbitkan diingat per request. Di response, token (atau bentuk digit polosnya) dikembalikan hanya untuk app `detokenize: true`. Streaming tidak pernah memotong token di tengah. Vault tidak bisa dijangkau → redaksi (kontrol yang lebih ketat).
- **Active-passive:** advisory lock Postgres; readiness `/ready` hanya untuk replika aktif, jadi Service hanya mengarah ke sana; client mencoba URL berikutnya bila mendapat 503 atau koneksi gagal.
- API vault berautentikasi bearer (`VAULT_CLIENT_TOKEN_SHA256`). Nilai melintas dalam cluster tanpa TLS sampai mTLS (tiket 40).

## Sisa
- Hak detokenisasi saat ini per app, belum per user/grup (butuh atribut identitas di gateway).
- Token yang kebetulan lolos validasi struktur (mis. NIK) bisa tercatat sebagai temuan di arah response.
