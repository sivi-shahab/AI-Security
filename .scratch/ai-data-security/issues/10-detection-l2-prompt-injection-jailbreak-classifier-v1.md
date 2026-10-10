# 10: Detection L2: prompt-injection & jailbreak classifier v1

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 04, 08
Spec: `../spec.md` §4.5 FR-PSEC-1..6, FR-PSEC-10; §9.2; §9.4

## Konteks
Deteksi serangan LLM di luar kemampuan regex.

## Scope
- Classifier biner + multi-label jenis serangan (direct, indirect, role confusion, exfil markdown, suffix).
- Fitur perplexity untuk adversarial suffix.
- Input dengan label `trust=untrusted` diperlakukan terpisah.
- Deteksi role marker palsu dan link/gambar markdown ke domain eksternal (rule L1 pendamping).
- Output `injection_score`, `attack_type[]`, evidence redacted.

## Acceptance criteria
- [ ] FPR benign ≤ 1% pada corpus benign. *(Belum. Holdout v1, 663 teks benign, model `l2-1` saja: 3,92% pada ambang 0,5 (taint sesi), 2,87% pada 0,7 (block untrusted), 1,36% pada 0,9 (block). L1 sendiri 0,45% / 0,30% / 0%. Ambang tidak disetel ke holdout.)*
- [x] Detection rate per teknik dilaporkan (encoding, multilingual, indirect, suffix). *(Tabel bawah: `evalcorpus l2eval` per teknik untuk L1, L2, dan L1+L2 pada tiap ambang policy.)*
- [ ] Kalibrasi ECE ≤ 0,05. *(Belum: ECE skor injection pada holdout 0,090. Platt di-fit pada dev split, bukan holdout.)*

Holdout v1, ambang 0,5 (rate terdeteksi):

| Teknik | n | L1 | L2 | L1+L2 |
|---|---:|---:|---:|---:|
| direct | 77 | 88,3% | 75,3% | 92,2% |
| roleplay | 34 | 0% | 52,9% | 52,9% |
| multilingual (jv/su/campur) | 22 | 18,2% | 72,7% | 81,8% |
| encoded (base64/hex/url/homoglyph/zero-width/tags) | 123 | 100% | 47–92% | 100% |
| indirect (html/email/pdf/tool) | 84 | 100% | 52,9–100% | 100% |
| role_confusion | 37 | 100% | 97,3% | 100% |
| exfil_markdown | 45 | 100% | 62,2% | 100% |
| gcg_suffix | 25 | 0% | 100% | 100% |
| public (deepset test) | 60 | 10,0% | 68,3% | 70,0% |
| **semua** | 507 | 72,4% | 75,5% | 91,3% |
| FPR benign / hard negative | 663 / 209 | 0,45% / 1,4% | 3,92% / 5,7% | 4,22% / 6,7% |

Ambang 0,9 (block): semua L1 15,6%, L2 55,0%, L1+L2 60,2%; FPR 0% / 1,36% / 1,36%. Ambang 0,7: 52,1% / 69,8% / 83,2%; FPR 0,30% / 2,87% / 3,02%. Jenis serangan L2 benar (jenis yang diharapkan ada di `types`): 42,7% dari 447. Latensi L2 (NER + injection, satu forward pass, klien → model-inference, `--cpus 2`): p50 18 ms, **p95 35 ms**, p99 86 ms (1.810 panggilan).

## Keputusan
- **Satu model untuk 09 dan 10** (`l2-1`): encoder yang sama dengan pii-ner-1, ditambah head sekuens (P(injection) + 5 jenis serangan), dilatih bersama. Satu forward pass untuk dua tugas membuat p95 gabungan 35 ms (budget 50 ms).
- **Data training, tanpa holdout:** data sintetis dengan frasa serangan, goal, lead, dan kosakata suffix GCG yang berbeda dari holdout (`TestTrainingDisjoint`), ditambah set publik berlisensi permisif, split train saja: deepset/prompt-injections (Apache-2.0; split test-nya ada di holdout), jackhhao/jailbreak-classification (Apache-2.0), SPML (MIT), dan alpaca-id-cleaned (CC-BY-4.0) sebagai benign berbahasa Indonesia. Revisi dan sha256 dicatat di `MODELS.json` (`train/fetch_public.py`). Teks yang sama dengan holdout dibuang.
- **Perplexity (FR-PSEC-4):** LM trigram karakter atas teks benign training. Skor = window 48 karakter paling "bukan bahasa" di 8 KB terakhir. Platt menggabungkan [logit, perplexity]. Suffix GCG holdout (kosakata tak pernah dilihat) terdeteksi 100%, L1 0%.
- **Encoding (FR-PSEC-3):** model tidak bisa membaca base64. detection-svc mengirim `views` (teks ternormalisasi dan setiap lapisan decode, `detect.Views`) dan view terburuk yang dihitung.
- **`trust=untrusted` (FR-PSEC-2):** diteruskan dari `context.trust` di `/scan/text`. Untuk konten untrusted, skor = max(P(injection), P(jenis indirect)), karena instruksi untuk AI di dalam data adalah serangannya. Tiap konten dinilai sendiri, tidak digabung dengan prompt user.
- **Jenis serangan** = sigmoid mentah ≥ 0,5. Temperature per jenis yang di-fit di dev (terpisah sempurna) jatuh ke batas bawah grid dan membuat semua jenis 0/1 di build pertama, jadi dibuang.
- **Rule L1 pendamping:** link markdown biasa (bukan gambar) yang query-nya placeholder (`UPPER_SNAKE` atau `{template}`) = `exfil_link` 0,6. Link dengan nilai query asli tetap aman. Role marker palsu sudah ada di L1 (tiket 08).
- **Penggabungan di detection-svc** (enforce): skor injection = max(L1, L2), jenis = gabungan (prefix `l2:`). Shadow tetap default.
- Gate int8 kini mengukur kesepakatan token hanya pada teks yang punya supervisi NER. Pada teks serangan head token tidak dilatih, sehingga near-tie di sana tidak bermakna. Hasilnya: token 0,9931, keputusan serangan 1,0.

## Hasil verifikasi lokal (2026-10-10)
- `go vet ./...` + `go test -race ./...` dengan Postgres 17 hijau; golangci-lint v2.5.0: 0 issue; ruff check + format bersih; `python -m unittest` (dengan model `l2-1`) hijau.

## Sisa
- **FPR > 1% dan ECE 0,090.** Set publik tidak mirip prompt bank. Hard negative sintetis menunjukkan FPR 5,7% pada 0,5. Langkah berikutnya: benign perusahaan berbahasa Indonesia yang lebih beragam (prompt internal yang sudah di-redact lewat antrean tiket 38), kalibrasi pada set yang mirip produksi, dan ambang/operating point policy dipilih pada set validasi, bukan holdout. Sampai itu terpenuhi, L2 tetap shadow. Di enforce, penggabungan max(L1, L2) pada ambang 0,5 akan menaikkan FPR dari 0,45% ke 4,22%.
- Lemah pada roleplay/persona (53%) dan URL/tag encoding tanpa decode L1. Jenis serangan hanya benar 43%.
- Bersama-sama ini menurunkan kalibrasi NER (ECE entitas 0,076 vs 0,032 pada pii-ner-1). Gate rilis §9.4 perlu ECE per head sebelum enforce.
- Skenario AgentDojo e-banking dan set "fresh attacks" bulanan belum ada di eval.
