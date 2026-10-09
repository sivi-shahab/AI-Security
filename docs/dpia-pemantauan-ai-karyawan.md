# DPIA: Pemantauan penggunaan AI oleh karyawan (inline proxy & browser extension)

Status: **DRAF, belum ditandatangani**
Versi: 0.1 (2026-10-10)
Pemilik: DPO, bersama Legal, HR, dan CISO
Tiket: 35 (gate untuk tiket 22 dan 23)
Spec: §10.2 (privasi, minimisasi), §17 (risiko monitoring karyawan)

> Dokumen ini disusun oleh tim platform sebagai bahan kerja. Penilaian hukum, putusan risiko akhir,
> dan tanda tangan menjadi wewenang DPO, Legal, dan HR. Pasal yang dikutip wajib dicek Legal
> terhadap teks resmi UU 27/2022 dan PP 33/2026 sebelum tanda tangan.

## 1. Mengapa DPIA diperlukan

UU PDP Pasal 34 mewajibkan penilaian dampak bila pemrosesan berpotensi berisiko tinggi, antara lain
pemantauan sistematis, pemrosesan skala besar, dan penggunaan teknologi baru. Rollout inline memenuhi
ketiganya:

- semua prompt, paste, dan upload karyawan ke domain AI diperiksa (sistematis, seluruh pegawai);
- skor risiko per pengguna dihitung (tiket 17, 25), yang termasuk evaluasi/penskoran;
- intersepsi TLS dan extension browser adalah teknologi baru bagi sebagian besar karyawan.

Detail tata cara DPIA di PP 33/2026 *(pasal belum diidentifikasi, Legal)*.

## 2. Deskripsi pemrosesan

| Aspek | Isi |
|---|---|
| Subjek data | Karyawan, kontraktor, dan vendor yang memakai perangkat/jaringan bank. Secara tidak langsung: nasabah dan pihak ketiga yang datanya ada di prompt atau file. |
| Kanal | Inline proxy lewat SWG/ICAP (tiket 23), browser extension managed Chrome/Edge (tiket 22). Kanal gateway AI dan MCP (tiket 13, 28) sudah berjalan dan berada di luar cakupan DPIA ini, kecuali skor risiko per pengguna. |
| Data yang diproses sesaat (in-memory) | Isi prompt, paste, file upload, dan respons ke/dari domain AI di katalog. Diperiksa oleh detection-svc internal, lalu dibuang. |
| Data yang disimpan | Metadata keputusan: waktu, kanal, app, aksi, kode alasan, kelas data dan jumlahnya, skor risiko, `principal_id` (HMAC), `content_hash` (HMAC), snippet ter-redact ≤ 200 karakter. Lihat Lampiran B. |
| Data yang disimpan hanya per policy eksplisit | Forensic capture: konten mentah, terenkripsi per insiden, TTL 30 hari, setiap unmask diaudit. |
| Penerima | SOC (triage insiden), CISO, DPO, auditor. Konten mentah hanya pemegang `evidence.unmask`. Tidak ada penerima di luar bank; tidak ada komponen offshore (ADR-0001). |
| Tujuan | (1) mencegah kebocoran data nasabah dan rahasia bank ke layanan AI pihak ketiga, (2) memenuhi kewajiban keamanan TI dan pengendalian AI bank (POJK 11/2022, Panduan AI OJK), (3) inventaris shadow AI. |
| Bukan tujuan | Penilaian kinerja, produktivitas, atau disiplin karyawan; pemantauan isi komunikasi di luar domain AI. |

## 3. Dasar hukum dan proporsionalitas

- **Dasar pemrosesan (UU PDP Pasal 20 ayat (2)).** Usulan: pemenuhan kewajiban hukum bank (keamanan
  sistem dan perlindungan data nasabah) dan kepentingan yang sah untuk mencegah kebocoran data.
  Persetujuan karyawan **tidak** dipakai sebagai dasar utama karena relasi kerja membuatnya tidak bebas.
  *(Putusan Legal.)* Bila kepentingan yang sah dipakai, Legal melengkapi uji keseimbangan.
- **Perlu dan proporsional.** Alternatif yang lebih ringan dan alasan tidak cukup:
  - *Pelatihan dan kebijakan saja:* tidak mencegah salah tempel data nasabah.
  - *Block total domain AI:* mendorong shadow AI lewat perangkat pribadi (§17), menghilangkan manfaat app sanctioned.
  - *Gateway AI internal saja (tiket 13):* tidak mencakup app publik di browser.
  - *Pemantauan inline dengan minimisasi* (pilihan): konten tidak disimpan, hanya metadata; aksi utama
    adalah coaching, bukan sanksi.
- **Cakupan dibatasi** ke domain di katalog AI (tiket 16). Lalu lintas non-AI tidak diperiksa oleh platform ini.

## 4. Risiko terhadap subjek data

Skala: kemungkinan × dampak, Rendah/Sedang/Tinggi. Risiko residual menunggu penilaian DPO.

| # | Risiko | Inheren | Mitigasi | Residual |
|---|---|---|---|---|
| R1 | Karyawan tidak tahu dipantau | Tinggi | Pemberitahuan sebelum rollout (Lampiran A), banner coaching menyebut pemantauan saat aksi pertama, intranet FAQ | Rendah |
| R2 | Konten pribadi (kesehatan, keluarga, keuangan pribadi) ikut terlihat | Tinggi | Konten tidak disimpan secara default; snippet ter-redact ≤ 200 karakter; event dengan field konten mentah ditolak di pipeline (`internal/events`); forensic capture hanya per policy eksplisit yang disetujui DPO | Sedang |
| R3 | Akun AI pribadi karyawan di perangkat kantor ikut diperiksa | Sedang | Deteksi akun corporate vs personal (tiket 22); policy untuk akun personal dibatasi block/coach tanpa forensic capture *(usulan, keputusan DPO)* | Sedang |
| R4 | Skor risiko pengguna dipakai untuk keputusan HR | Tinggi | Larangan tertulis di kebijakan (Lampiran A §4); skor hanya terlihat SOC/CISO; tidak ada keputusan otomatis terhadap karyawan; setiap tindak lanjut HR lewat proses insiden dengan peninjauan manusia | Sedang |
| R5 | Penyalahgunaan akses ke konten mentah | Tinggi | `evidence.unmask` butuh re-auth + justifikasi, setiap akses dan penolakan masuk audit log hash-chain (tiket 07); review akses unmask bulanan oleh DPO | Rendah |
| R6 | Identifikasi ulang dari analitik | Sedang | `principal_id` HMAC dengan pepper per tenant; re-identifikasi hanya peran berhak | Rendah |
| R7 | Retensi berlebihan | Sedang | TTL §10.2 (Lampiran B); temp file extraction 1 jam | Rendah |
| R8 | Justifikasi teks bebas dari user (coaching, tiket 22) berisi data pribadi | Sedang | Justifikasi dibatasi panjangnya dan melewati detektor yang sama sebelum disimpan *(syarat implementasi tiket 22)* | Rendah |
| R9 | Intersepsi TLS memecah privasi untuk situs non-AI (perbankan pribadi, kesehatan) | Tinggi | Bypass TLS inspection untuk kategori sensitif di SWG; adapter ICAP hanya menerima domain katalog AI *(syarat implementasi tiket 23)* | Rendah |
| R10 | Kebocoran data pemantauan itu sendiri | Sedang | Enkripsi at rest, RLS tenant, tanpa komponen offshore, audit log WORM | Rendah |

## 5. Hak subjek data

- **Informasi:** Lampiran A, dikirim sebelum rollout dan tersedia di intranet.
- **Akses dan koreksi:** permintaan lewat DPO; data yang tersedia adalah metadata event milik
  pemohon (dicari lewat HMAC `principal_id`). Konten tidak ada kecuali forensic capture.
- **Keberatan:** lewat DPO/HR; tidak menghentikan pemantauan yang didasarkan kewajiban hukum, tetapi
  dicatat dan ditinjau.
- **Keputusan otomatis:** tidak ada keputusan otomatis dengan akibat hukum terhadap karyawan. Block oleh
  policy hanya mencegah satu transfer data dan selalu menyediakan jalur alternatif (app sanctioned).

## 6. Konsultasi

| Pihak | Status |
|---|---|
| DPO | belum |
| Legal | belum |
| HR | belum |
| CISO | belum |
| Perwakilan karyawan / serikat pekerja (bila ada perjanjian kerja bersama yang mensyaratkan) | belum, HR menentukan |

## 7. Keputusan dan tanda tangan

Rollout inline (tiket 22, 23) ke produksi **tidak boleh** dilakukan sebelum bagian ini lengkap.
Setelah ditandatangani, PDF bertanda tangan dilampirkan sebagai bukti compliance:

```
POST /compliance/evidence
{"control_id":"CTL-DLP","status":"pass","sha256":"<sha256 PDF>","note":"DPIA pemantauan AI karyawan v1.0 ditandatangani"}
```

| Peran | Nama | Putusan (setuju / setuju bersyarat / tolak) | Syarat | Tanggal |
|---|---|---|---|---|
| DPO | | | | |
| Legal | | | | |
| HR | | | | |
| CISO | | | | |

Review ulang: setiap perubahan cakupan (kanal baru, forensic capture baru, endpoint agent tiket 36),
atau paling lambat 12 bulan.

---

## Lampiran A: Draf kebijakan penggunaan AI dan pemberitahuan pemantauan

*(Untuk disesuaikan HR dan Legal, dikirim ke seluruh karyawan minimal 14 hari sebelum rollout.)*

**1. Tujuan.** Bank mendukung penggunaan AI yang aman. Kebijakan ini mengatur app AI yang boleh dipakai
dan menjelaskan pemantauan yang bank lakukan untuk mencegah kebocoran data nasabah dan rahasia bank.

**2. App yang boleh dipakai.** Daftar app AI *sanctioned* ada di intranet. App lain dapat diblokir atau
dibatasi. Permintaan app baru diajukan lewat [kanal].

**3. Data yang tidak boleh dimasukkan ke AI** di luar app sanctioned: data nasabah (NIK, rekening, kartu),
data karyawan lain, kredensial dan secret, kode sumber internal, dokumen berklasifikasi rahasia.

**4. Apa yang dipantau dan bagaimana.**
- Saat Anda mengirim prompt, menempel teks, atau mengunggah file ke layanan AI dari perangkat atau jaringan
  bank, isinya diperiksa otomatis untuk mencari data sensitif.
- Bank **menyimpan catatan** berupa waktu, app, jenis data sensitif yang terdeteksi, dan tindakan yang diambil.
  Bank **tidak menyimpan isi** prompt atau file Anda, kecuali pada kasus pelanggaran tertentu yang ditetapkan
  kebijakan dan disetujui DPO; isi tersebut dienkripsi, dihapus setelah 30 hari, dan setiap aksesnya dicatat.
- Identitas Anda di laporan analitik disamarkan.
- Pemantauan ini **tidak** dipakai untuk menilai kinerja atau produktivitas, dan tidak ada sanksi yang diputuskan
  otomatis oleh sistem.
- Situs non-AI (perbankan pribadi, kesehatan, dll.) tidak diperiksa oleh sistem ini.

**5. Apa yang akan Anda lihat.** Peringatan dengan penjelasan dan alternatif, permintaan alasan, penyamaran
data otomatis, atau pemblokiran.

**6. Hak Anda.** Anda dapat meminta informasi tentang catatan yang terkait dengan Anda, mengajukan koreksi, atau
keberatan melalui DPO: [kontak].

**7. Retensi.** Lampiran B.

---

## Lampiran B: Konfigurasi minimisasi untuk persetujuan DPO

Nilai yang berlaku di kode saat ini. DPO menyetujui atau meminta perubahan per baris.

| Item | Nilai | Ditegakkan di | Disetujui DPO |
|---|---|---|---|
| Konten mentah di event/log | dilarang; event dengan field `prompt`, `response`, `content`, `body`, `raw`, `text`, `file_content`, dll. ditolak | `internal/privacy/forbidden_fields.txt`, `internal/events/events.go` (`Check`) | |
| Snippet | ≤ 200 karakter, sudah di-redact oleh PEP; deret ≥ 12 digit ditolak sebagai identifier mentah | `internal/events/decision_event.v1.json`, `internal/events/events.go` | |
| Identitas pengguna | HMAC-SHA256 dengan pepper per tenant (`principal_id`) | `decision_event.v1.json` | |
| Hash konten | HMAC-SHA256 dengan pepper per tenant | `decision_event.v1.json` | |
| Forensic capture | mati secara default; hidup hanya per rule policy `forensic_capture`; terenkripsi DEK per insiden | `internal/incident/store.go` (`AddRawEvidence`) | |
| TTL evidence raw | 30 hari | `internal/incident/store.go` (`RawTTL`) | |
| Unmask | `evidence.unmask` + re-auth + justifikasi; diaudit, termasuk penolakan | `internal/incident/store.go` (`Unmask`) | |
| TTL decision event | 400 hari (90 hari hot) | spec §10.2, tiket 15 | |
| TTL temp file extraction | 1 jam | spec §10.2 | |
| Audit log | ≥ 5 tahun WORM | `deploy/base/audit-anchor.yaml` | |
| Rule policy yang mengaktifkan forensic capture | *daftar diisi saat policy tiket 22/23 disusun* | policy bundle | |
| Akun AI personal | block/coach, tanpa forensic capture *(usulan R3)* | policy tiket 22 | |
| Bypass TLS kategori sensitif | aktif *(usulan R9)* | konfigurasi SWG, tiket 23 | |
