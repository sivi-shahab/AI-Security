# 08: Detection L1: normalisasi + regex + validator + secrets

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 04, 05
Spec: `../spec.md` §4.4 FR-CLS-1..4; §4.5 FR-PSEC-3; §9.1

## Konteks
Fast path deterministik dengan budget ≤ 10 ms. Semua PEP bergantung padanya.

## Scope
- Normalizer: NFKC, strip zero-width & tag Unicode, homoglyph map, decode berlapis (base64/hex/URL/ROT13) dengan depth ≤ 3.
- Validator: NIK (struktur wilayah + tanggal lahir, perempuan +40), KK, NPWP 15/16 digit, No. HP +62/08, PAN (Luhn + BIN), rekening (format bank).
- Secret detection: pola API key vendor, PEM, JWT, connection string + entropy.
- Output per match: `{type, confidence, span_offsets, validator_passed, context_score}` + agregasi sensitivity (FR-CLS-3).
- Endpoint `POST /scan/text` (tanpa policy dulu).

## Acceptance criteria
- [ ] Precision ≥ 0,95 dan recall ≥ 0,90 pada kelas P0 di eval set v1 (tiket 04). *(Eval set v1 belum ada. Sementara `TestSyntheticEval`, 5000 dokumen sintetis berseed (template dokumen bank + negatif: nominal, tanggal, nomor ref/invoice, prosa "password: diperlukan"), menegakkan target per kelas: NIK, NPWP, HP, PAN, rekening, AWS key, connection string semuanya P/R 1,000. Ganti dengan holdout 04 saat beku.)*
- [x] p95 ≤ 10 ms untuk teks 8K token. *(`TestLatencyBudget`: 32 KB, p50 4,2 ms / p95 5,5 ms lokal; di-skip di bawah `-race`. `BenchmarkScan8K` ±4,6 ms/op.)*
- [x] Test untuk tiap validator: kasus valid, invalid, dan tepi. *(`validators_test.go`: NIK (+40, 29 Feb, provinsi Papua baru, nol), KK, NPWP 15/16, PAN per issuer + panjang, HP per prefix/panjang.)*
- [x] Fuzz test normalizer/decoder. *(`FuzzScan`: peta offset konsisten, span di dalam teks, Redact tidak panic; 60 detik, ±550 ribu eksekusi, bersih.)*

## Keputusan
- Paket `internal/detect` (Go, tanpa I/O); `detection-svc` mengekspos `POST /scan/text` (≤ 256 KB, 413 bila lebih) tanpa policy. Respons: `sensitivity`, `classes[{type,count,confidence}]` (bentuk `content.classes` input PDP), `matches[{type, confidence, span_offsets, validator_passed, context_score, encoding}]`. Nilai yang cocok tidak pernah dikembalikan atau di-log; `span_offsets` = byte UTF-8 teks asli.
- Normalisasi per segmen NFKC dengan peta offset per byte ke teks asli, jadi deteksi berjalan di teks ternormalisasi tetapi redaksi (`detect.Redact`) mengenai byte asli (fullwidth, zero-width, homoglyph ikut terhapus). Zero-width/bidi/variation selector dibuang; homoglyph Kiril/Yunani dan digit Arab-Indic/Devanagari/Bengali/Thai dilipat ke ASCII.
- Decode berlapis ≤ 3: base64 (std/url, padded/raw), hex, URL (`%XX`), plus ROT13 (hanya secrets, karena ROT13 tidak mengubah digit) dan karakter tag Unicode (ASCII smuggling, didekode bukan sekadar dibuang). Hasil decode harus ≥ 90% printable; match di dalam blob melaporkan span seluruh blob dan `encoding` (mis. `base64/url`).
- Angka: satu pemindai deret digit (pemisah spasi/titik/strip), jendela grup terpanjang dengan confidence tertinggi, sehingga "NIK … 0812…" tetap dua temuan. Tanpa konteks: NIK 0,85, PAN (Luhn + BIN + panjang issuer) 0,90, HP 0,90 (+62: 0,95), NPWP format bertitik 0,95. Dengan kata kunci ±48 byte: 0,95–0,99. KK, NPWP 15 digit polos, dan rekening wajib konteks. Nama bank hanya mengunci panjang rekening (BCA/BNI/BSI 10, Mandiri 13, BRI 15), bukan konteks, karena nama bank ada di semua dokumen bank. Label "ref/invoice/order/trx/resi" menggugurkan angka tanpa konteks positif.
- Secrets: pola vendor (AWS, GitHub, GitLab, Slack, Google, OpenAI/Anthropic, Stripe), PEM private key, JWT (header harus JSON dengan `alg`), connection string URL dan ADO (password wajib ada), `password=` (bukan placeholder, ≥ 2 kelas karakter), dan `api_key/secret/token=` dengan entropi ≥ 3,5 bit/karakter. Angka di dalam secret tidak dilaporkan sebagai PII.
- Ambang lapor 0,8 (`detect.Threshold`). Sensitivity (FR-CLS-3): SECRET → `restricted`; PII/PCI/FIN → `confidential`; ≥ 10 nilai berbeda satu tipe → `restricted`; tanpa temuan → `internal` (konten korporat; `public` hanya lewat label eksternal FR-CLS-6).
- Regex Go (NFA) di seluruh teks ternyata 10× di atas budget (p95 98 ms). Kini aturan secret di-anchor (satu pass tabel byte pertama, lalu regex `^` di jendela ≤ 8 KB), sedangkan deret digit dan kandidat blob dipindai manual.

## Hasil verifikasi lokal (2026-10-03)
- `go test -race ./...` hijau; golangci-lint 0 issue; fuzz 60 detik bersih; image `detection-svc` ter-build dan `POST /scan/text` di-smoke-test (NIK fullwidth, rekening BCA, AWS key dalam base64).

## Sisa / follow-up
- Eval holdout v1 (tiket 04) untuk AC precision/recall yang sebenarnya.
- Kelas FR-CLS-1 lain (paspor, CIF, BPJS/ICD-10, alamat/nama) butuh kamus/NER: tiket 09.
- Format rekening bank lain (termasuk Bank Mega) ditambahkan ke `accountLengths` saat formatnya terkonfirmasi.
- `POST /scan/text` belum berautentikasi; bergantung pada isolasi jaringan cluster. Tambahkan NetworkPolicy/mTLS saat PEP pertama memanggilnya (tiket 28).
