# 37: Similarity & fingerprint dokumen rahasia

Status: needs-gitlab-run
Type: task
Priority: P2
Milestone: M4
Blocked by: 08
Spec: `../spec.md` §4.4 Source Code/IP; §9.1 L3; §9.2

## Konteks
Mendeteksi kebocoran IP/dokumen rahasia yang tidak berpola.

## Scope
- Registrasi corpus rahasia; MinHash/SimHash near-dup + sentence embedding.
- Jalur async untuk file dan opsional inline untuk teks pendek.

## Acceptance criteria
- [x] Precision/recall pada eval set dokumen rahasia sintetis. *(`TestEval`: 200 dokumen terdaftar + 200 tidak terdaftar dari generator yang sama, dengan boilerplate surat bank yang sama (jebakan false positive). Recall 1,000 untuk dokumen utuh, excerpt verbatim 40 dan 150 kata di dalam prompt, excerpt 80 kata yang diformat ulang (huruf besar, tanda baca, baris baru), dan excerpt 120 kata dengan 1 dari 12 kata diganti. Edit 1 dari 6 kata (di luar jaminan): recall 0,90. Precision total 0,9992, yaitu 1 false positive dari 1.700 negatif (termasuk 500 prompt yang hanya berbagi boilerplate). Parafrase tidak terdeteksi, lihat Sisa.)*
- [x] Inline tetap dalam budget latensi. *(`TestLatency`: teks 6k kata (~8K token) terhadap 1.000 dokumen terdaftar: p50 5–7 ms, p95 11–17 ms di mesin ber-load 8; asersi p95 ≤ 20 ms, di dalam budget L2 50 ms dan overhead gateway 80 ms.)*

## Keputusan
- **Winnowing, bukan MinHash/SimHash** (`internal/similarity`). Kebocoran biasanya potongan dokumen di dalam prompt. MinHash/SimHash mengukur kemiripan dokumen utuh, sehingga potongan pendek di dalam teks panjang lolos. Winnowing (Schleimer dkk., SIGMOD 2003) atas shingle 5 kata dengan window 4 **menjamin** setiap rangkaian verbatim ≥ 8 kata menghasilkan fingerprint bersama, berapa pun panjang teks di sekitarnya (`TestWinnowGuarantee`). Kata di-lowercase dan tanda baca/spasi diabaikan.
- **Aturan hit:** minimal 3 fingerprint bersama dalam 16 fingerprint berurutan (~40 kata), artinya ada satu passage ~15+ kata yang disalin. Kolisi kebetulan antar teks yang tidak berkaitan tersebar satu per satu dan tidak membentuk klaster (di eval, aturan ini menurunkan FP dokumen utuh dari 4/200 ke 1/200). Fingerprint yang muncul di ≥ 3 dokumen terdaftar dianggap template (kop surat, klausul standar) dan diabaikan.
- **Privasi:** hanya fingerprint ber-HMAC (pepper tenant) yang disimpan, teks dibuang setelah fingerprinting; dedupe lewat HMAC konten. Tanpa pepper, set fingerprint tidak bisa dicocokkan dengan teks tebakan.
- **Output:** kelas `CODE.CONFIDENTIAL_DOC` (count = jumlah dokumen), match dengan span (bisa dipakai `Redact`; sampai 3 kata di tepi passage bisa tidak tercakup), sensitivity dinaikkan ke sensitivity dokumen (`confidential`/`restricted`). Confidence = 0,8 + 0,2 × containment.
- **Registrasi** (control-plane, `policy.write` = DLP analyst): `POST /similarity/docs?name=&sensitivity=` (body = file; format sesuai `internal/extract`, PDF butuh `TIKA_URL`), `GET /similarity/docs` (`policy.read`), `DELETE /similarity/docs/{id}`. Register/unregister diaudit di transaksi yang sama.
- **Jalur inline:** `detection-svc POST /scan/text` menambahkan hit ke hasil L1 plus `similar[]` (id/nama dokumen, shared, containment, coverage). Opsional: tanpa `DATABASE_URL` hanya L1.
- **Jalur async file:** scan data-at-rest (`datascan`, tiket 31–33), sehingga salinan dokumen rahasia di OneDrive/Drive/bucket ikut terklasifikasi dan masuk skor exposure.
- Index di memori per replika, di-reload ≤ 60 detik setelah korpus berubah; reload yang gagal mempertahankan index lama.

## Hasil verifikasi lokal (2026-10-10)
- `go test -race ./...` dengan Postgres: semua hijau **kecuali `internal/mcpgw` `TestKillSwitch`** (session terputus 2,9 s, batas 2 s). Gagal juga di HEAD sebelum tiket ini dan mcpgw tidak menyentuh paket yang diubah: masalah lama, perlu dicek terpisah. golangci-lint 0 issue.

## Sisa
- **Embedding similarity untuk parafrase**: menunggu model self-hosted di `model-inference` (tiket 09/10 belum ada model; DEC-4 melarang API eksternal).
- `POST /scan/file` (§8.2) belum ada; file ke app AI baru tercakup di data-at-rest.
- MCP gateway (hasil tool ke agent) belum memakai index ini.
- Korpus template bank (kop surat, klausul standar) yang bisa didaftarkan sebagai "bukan rahasia" bila FP di produksi lebih tinggi dari eval.
- Eval memakai korpus sintetis; ulangi dengan sampel dokumen rahasia nyata (di lingkungan bank) sebelum policy `block` diaktifkan.
