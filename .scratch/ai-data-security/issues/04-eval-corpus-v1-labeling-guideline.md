# 04: Eval corpus v1 & labeling guideline

Status: needs-signoff
Type: task
Priority: P0
Milestone: M0
Spec: `../spec.md` §9.3; §9.4

## Konteks
Semua detektor butuh eval set beku untuk gate rilis model (§9.4).

## Scope
- Generator sintetis PII Indonesia: NIK, KK, NPWP, rekening, No. HP, dan PAN (valid secara struktur, fiktif), disisipkan ke template dokumen bank.
- Corpus prompt injection/jailbreak: direct, indirect (HTML/PDF/email), encoded, multibahasa ID/EN, dan GCG-style suffix, dari dataset berlisensi terbuka + buatan sendiri.
- Corpus benign ala enterprise untuk mengukur FPR.
- Guideline labeling per kelas, double labeling, dan target κ ≥ 0,8.
- Provenance tiap dataset: sumber, lisensi, versi, hash.

## Acceptance criteria
- [x] Eval set holdout v1 dibekukan dan di-hash. *(`data/eval/v1/`: 640 PII sintetis, 447 injection sintetis, 607 benign sintetis, 116 sampel publik (deepset/prompt-injections test, Apache-2.0, revisi `4f61ecb`). `MANIFEST.json` mencatat sumber, lisensi, revisi/seed, dan sha256 per file. `evalcorpus.Load` menolak file yang berubah; `TestHoldoutFrozen` memastikan file sintetis identik dengan keluaran generator+seed yang tercatat.)*
- [ ] Laporan inter-annotator agreement ≥ 0,8. *(Alat dan proses siap: `evalcorpus sheet` (lembar buta), `evalcorpus kappa` (Cohen's κ per pertanyaan, gagal < 0,8), guideline `docs/labeling-guideline.md`. Menunggu dua annotator dari bank; hasilnya disimpan di `data/eval/v1/AGREEMENT.md`.)*
- [x] Tidak ada data nasabah asli di corpus. *(NIK/KK/NPWP/HP/rekening = digit acak yang valid secara struktur; kartu = nomor test resmi jaringan kartu (dicek test); nama = kombinasi nama umum. `TestPublicSetHasNoPII`: set publik tanpa temuan data sensitif.)*

## Keputusan
- **Generator Go deterministik** (`internal/evalcorpus`, `GeneratorVersion` + seed): template dokumen bank ID/EN (surat kuasa, formulir pembukaan rekening, chat CS, rekap transfer, profil nasabah, dll.) dengan span byte per entitas; nomor referensi/invoice berawalan `00` sebagai hard negative yang labelnya tidak ambigu. Serangan per teknik (direct, roleplay, role confusion, indirect HTML/email/PDF/tool result, exfil markdown, 6 jenis encoding, Jawa/Sunda/campuran, suffix gaya GCG), disisipkan ke permintaan biasa. Benign enterprise + 209 hard negative (membahas injection, "abaikan email sebelumnya", catatan untuk tim, gambar markdown internal).
- **Set dev** dibuat dengan seed lain (`evalcorpus freeze -dir <dir> -seed N`), tidak di-commit. Holdout v1 tidak boleh dipakai untuk tuning.
- **Runner** `evalcorpus score`: precision/recall/F1 per kelas (level span), FPR benign, detection rate per teknik. Bentuk `Detector` sama dengan `detect.Scan`, jadi L2 (09, 10) tinggal dibungkus.

## Baseline detection L1 di holdout v1
Data sensitif: PHONE F1 1,00; NPWP 0,997; ACCOUNT 0,995; PAN 0,988; NIK 0,936 (precision 0,888); **KK recall 0,658**. Benign dengan temuan PII: 0%. NIK FP dan KK FN berasal dari kasus yang sama: nomor KK (struktur identik dengan NIK) dilaporkan sebagai NIK. Ini input untuk tiket 09 (konteks/NER).

Injection pada ambang 0,8 (floor risk): direct 88%, semua encoding 100%, role confusion 35%, multilingual 18%, publik 10%, sedangkan indirect, exfil, roleplay, dan GCG 0%. Pada ambang 0,6: indirect dan role confusion 100%, exfil 76%. FPR benign 0,30% (0,8) / 0,45% (0,6); pada hard negative 1,0% / 1,4%.

**Bias yang diketahui:** template serangan sintetis ditulis dengan mengetahui rule L1, sehingga angka indirect/encoding/role confusion terlalu optimistis untuk L1. Angka set publik (10%) dan set fresh red team adalah ukuran yang jujur; classifier L2 (tiket 10) harus dinilai terutama di sana. Set publik berbahasa Inggris/Jerman, jadi ID/campuran masih perlu sumber terbuka tambahan.

## Sisa
- Double labeling oleh dua annotator bank, adjudikasi, dan `AGREEMENT.md` (κ ≥ 0,8).
- Dataset publik tambahan berbahasa Indonesia (belum ditemukan yang berlisensi jelas) dan set fresh attacks bulanan dari red team.
