# 50: Scan file hanya memeriksa 2 MiB teks pertama

Status: needs-triage
Type: bug
Priority: P1
Milestone: M2
Blocked by: -
Spec: `../spec.md` §13.1 (file scan sync ≤ 5 MB, async ≤ 50 MB); FR-DATA; temuan tiket 21 (`docs/nfr/m1-report.md`)

## Konteks
Pengukuran tiket 21 (`deploy/nfr/nfr filescan`): zip CSV berisi NIK, 5 MB maupun 49 MB, menghasilkan jumlah temuan L1 yang **sama** (2.804) dan waktu yang sama (~0,37 detik p95). `extract.Default.MaxText` = 2 MiB memotong teks yang diserahkan ke detektor (`Result.Truncated`). Isi file setelah 2 MiB tidak diperiksa sama sekali, sehingga data sensitif yang ditaruh di akhir file lolos. Angka latensi file scan memenuhi target justru karena pemotongan ini.

## Scope
- Scan berjendela atas seluruh teks (streaming per chunk dengan overlap) untuk jalur async sampai batas file 50 MB. Untuk sync, tetapkan batas yang tetap memenuhi p95 ≤ 2 detik.
- Bila pemotongan tetap ada, `Truncated` harus menjadi sinyal policy (mis. `content.truncated` → `require_approval`/`block` untuk app `restricted`), bukan diam-diam lolos.
- Ukur ulang dengan `deploy/nfr/.bin/nfr filescan -mb 5` dan `-mb 49`.

## Acceptance criteria
- [ ] NIK di byte terakhir file 49 MB terdeteksi (test).
- [ ] p95 sync 5 MB ≤ 2 detik, async 50 MB ≤ 60 detik dengan seluruh teks diperiksa.
