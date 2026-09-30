# 04: Eval corpus v1 & labeling guideline

Status: needs-triage
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
- [ ] Eval set holdout v1 dibekukan dan di-hash.
- [ ] Laporan inter-annotator agreement ≥ 0,8.
- [ ] Tidak ada data nasabah asli di corpus.
