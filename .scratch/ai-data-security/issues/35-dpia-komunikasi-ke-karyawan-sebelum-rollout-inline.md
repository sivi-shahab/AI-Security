# 35: DPIA & komunikasi ke karyawan sebelum rollout inline

Status: needs-signoff
Type: task
Priority: P1
Milestone: M2
Spec: `../spec.md` §10.2 minimisasi; §17 risiko monitoring

## Konteks
Inline proxy dan extension memantau aktivitas karyawan secara sistematis.

## Scope
- DPIA bersama DPO/Legal/HR.
- Kebijakan penggunaan AI internal + transparansi pemantauan.
- Konfigurasi minimisasi (snippet, forensic capture) disetujui DPO.

## Acceptance criteria
- [ ] DPIA ditandatangani sebelum tiket 22/23 dirilis ke produksi. *(Draf siap: `docs/dpia-pemantauan-ai-karyawan.md`. Tanda tangan DPO/Legal/HR/CISO belum. Gate: tiket 22 dan 23 kini `Blocked by: 35` untuk rilis produksi, dan syarat DPIA R3/R8/R9 masuk ke AC keduanya.)*

## Hasil (2026-10-10)
- **DPIA draf v0.1**: deskripsi pemrosesan, dasar hukum (usulan kewajiban hukum + kepentingan sah, bukan persetujuan karyawan), uji perlu/proporsional terhadap alternatif, 10 risiko dengan mitigasi yang dirujuk ke kode, hak subjek data, tabel konsultasi dan tanda tangan.
- **Lampiran A**: draf kebijakan penggunaan AI + pemberitahuan pemantauan, termasuk larangan memakai skor risiko untuk penilaian kinerja/HR.
- **Lampiran B**: konfigurasi minimisasi yang berlaku di kode (forbidden fields, snippet ≤ 200 + tolak deret digit, HMAC principal/konten, forensic capture opt-in, TTL raw 30 hari, unmask teraudit, retensi) dengan kolom persetujuan DPO per baris.
- DPIA bertanda tangan dilampirkan sebagai bukti lewat `POST /compliance/evidence` (CTL-DLP).
- Spec §10.2: "pertimbangkan DPIA" → DPIA wajib sebelum rollout inline.

## Sisa
- Legal: cek kutipan UU PDP Ps. 20 dan 34 terhadap teks resmi, cari pasal DPIA di PP 33/2026, putuskan dasar pemrosesan (dan uji keseimbangan bila kepentingan sah).
- HR: perlu tidaknya konsultasi perwakilan karyawan/PKB; kirim Lampiran A ≥ 14 hari sebelum rollout.
- DPO: putusan risiko residual dan persetujuan tiap baris Lampiran B.
