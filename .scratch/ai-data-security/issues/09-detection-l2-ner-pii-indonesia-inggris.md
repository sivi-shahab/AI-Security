# 09: Detection L2: NER PII Indonesia/Inggris

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 04, 08
Spec: `../spec.md` §9.2; §9.4

## Konteks
Entitas tanpa pola tetap (nama, alamat, diagnosis) butuh model NER.

## Scope
- Fine-tune encoder multibahasa kecil, lalu distilasi ke ONNX int8.
- Serving lewat model-inference (Triton/ONNX Runtime) di CPU.
- Integrasi ke detection-svc dengan timeout dan fallback ke hasil L1.
- Model card + versi model di setiap respons.

## Acceptance criteria
- [x] F1 per entitas dilaporkan; ECE ≤ 0,05. *(`evalcorpus l2eval` pada holdout v1, model int8 yang di-serve: ECE confidence entitas 0,032 (1.572 entitas). F1 L2 per entitas di tabel bawah. Nama dan alamat dinilai dengan gold yang diturunkan dari replay generator holdout (`evalcorpus nergold`, `TestPIIFull`), tanpa mengubah holdout.)*
- [ ] p95 L2 ≤ 50 ms (bersama classifier injection). *(Belum: p95 62 ms, p50 31 ms, diukur klien → model-inference (`--cpus 2`, `ORT_THREADS=2`) saat host sedang dipakai training lain (load 12–20 di 16 core). Pengukuran bersama classifier injection ada di tiket 10.)*
- [x] Model dirilis lewat shadow mode dulu. *(`L2_MODE` default `shadow`, juga di `deploy/base/services.yaml`: temuan L2 dilaporkan di `l2` respons `/scan/text`, hasil tidak berubah. `enforce` menggabungkannya (`TestShadowEnforceFallback`).)*

Hasil holdout v1 (`pii-ner-1+46960d7d86e0`, ambang 0,5):

| Kelas | L1 F1 | L2 P | L2 R | L2 F1 | L1+L2 F1 |
|---|---:|---:|---:|---:|---:|
| PII.NAME | 0 | 0,886 | 0,861 | 0,873 | 0,873 |
| PII.ADDRESS | 0 | 0,976 | 1,000 | 0,988 | 0,988 |
| PII_ID.NIK | 0,936 | 0,869 | 0,787 | 0,826 | 0,936 |
| PII_ID.KK | 0,794 | 1,000 | 0,608 | 0,756 | 0,794 |
| PII_ID.NPWP | 0,997 | 1,000 | 0,725 | 0,841 | 0,997 |
| PII_ID.PHONE | 1,000 | 1,000 | 0,833 | 0,909 | 1,000 |
| FIN.ACCOUNT | 0,995 | 0 | 0 | 0 | 0,995 |
| PCI.PAN | 0,988 | 0 | 0 | 0 | 0,988 |
| PHI.DIAGNOSIS | – | – | – | – | – (holdout tidak punya diagnosis) |

## Keputusan
- **Model:** `distilbert-base-multilingual-cased` (Apache-2.0, revisi dipin) dengan head token BIO untuk 9 label (nama, alamat, diagnosis, NIK, KK, NPWP, telepon, PAN, rekening). Hanya 3 dari 6 layer transformer yang dipakai, embedding kata dibekukan, window 128 token stride 32. Alasannya CPU: di host ini satu step training 6 layer ~25 detik (host dipakai bersama), 3 layer ~3,5–6 detik, dan inferensi juga lebih ringan untuk budget 50 ms. "Distilasi" diwujudkan sebagai pemotongan layer dari model yang sudah hasil distilasi, bukan teacher-student. Training: 2 epoch, ~40 menit di CPU.
- **Data training tanpa holdout dan tanpa data nasabah:** `evalcorpus train` (generator baru `evalcorpus-train/1`). Template, nama, jalan, kota, dan bentuk alamat semuanya berbeda dari holdout (`TestTrainingDisjoint`). Teks yang kebetulan sama dengan holdout dibuang oleh trainer. Identifier valid secara struktur dan fiktif.
- **Kalibrasi:** temperature token, lalu Platt scaling per entitas yang di-fit pada template yang *ditahan* dari training (dev split per template). Kalibrasi pada dev acak dari template yang sama membuat semua confidence terlihat benar (dev accuracy 1,0, ECE holdout 0,133). Dengan dev per template: ECE dev 0,258 → 0,058, ECE holdout 0,032.
- **Kuantisasi int8:** dynamic, per-channel, reduce_range, MatMul saja, head output tetap fp32. Temuan: int8 per-tensor default di CPU AVX2 tanpa VNNI mengacak logit (kesepakatan token dengan fp32 hanya ~50%; model pertama keluar sampah). Trainer kini menolak merilis bila kesepakatan int8 vs fp32 < 99% (`ship`); hasil 0,9932.
- **Serving:** model-inference (Python, ONNX Runtime CPU, distroless, deps multi-stage) `POST /v1/analyze` → entitas dengan offset byte UTF-8 + versi `version+sha`. `/readyz` hanya siap bila model termuat. Model tidak di-bake ke image: dipasang dari PVC `model-store` dan dipin per file di `services/model-inference/MODELS.json`. Konten tidak pernah dilog.
- **Integrasi detection-svc** (`internal/l2`): L1 (dan tuning tenant), lalu L2 dengan timeout `L2_TIMEOUT` (default 80 ms). Timeout, error, atau model mati → hasil L1 tetap, `l2.status` = timeout/error. Short-circuit: private key → L2 dilewati. Mode enforce (`detect.WithL2`): model hanya *menambah* nama, alamat, dan diagnosis serta mengganti label NIK↔KK. L1 tetap otoritas untuk identifier berpola, karena di holdout temuan NPWP/rekening versi model banyak yang salah (presisi NPWP gabungan sempat turun 0,997 → 0,708 sebelum aturan ini). Diagnosis = data kesehatan → sensitivitas `restricted`.
- Model card: `services/model-inference/MODEL_CARD.md`. Reproduksi: `train/data.sh`, `train/Dockerfile`, `train/train.py`, `evalcorpus l2eval`.

## Hasil verifikasi lokal (2026-10-10)
- `go vet ./...` + `go test -race ./...` dengan Postgres 17 hijau; golangci-lint v2.5.0: 0 issue; ruff check + format bersih; `python -m unittest` (termasuk test model sungguhan dengan `MODEL_DIR`) hijau.
- Image model-inference distroless dibangun dan jalan (`/healthz`, `/readyz` 503 tanpa model).

## Sisa
- p95 ≤ 50 ms belum terbukti (62 ms di host yang sibuk). Ukur ulang di node yang tidak berbagi CPU; opsi: 2 layer, batch per request, atau thread lebih banyak.
- NIK vs KK belum lebih baik dari L1 (KK recall 0,66). Perlu data training dengan konteks KK yang lebih bervariasi, atau aturan konteks L1.
- `PHI.DIAGNOSIS` dilatih tapi tidak terukur: holdout v1 tidak punya diagnosis. Butuh eval set v2 dengan dokumen kesehatan (label ganda κ ≥ 0,8).
- Semua data (train dan holdout) sintetis: angka ini batas atas untuk produksi. Eval pada dokumen nyata yang sudah di-redact (active learning, tiket 38) sebelum pindah ke enforce.
- Job rilis yang menyalin artefak ke PVC `model-store` dengan cek sha256 `MODELS.json` belum dibuat.
