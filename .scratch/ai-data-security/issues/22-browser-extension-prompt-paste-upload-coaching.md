# 22: Browser extension: prompt/paste/upload + coaching

Status: deferred
Type: task
Priority: P1
Milestone: M3+
Blocked by: 08, 11, 16, 35 (rilis produksi)
Spec: `../spec.md` §4.2 FR-SHADOW-2, FR-SHADOW-5; §4.6; §5.4

## Konteks
Menangkap penggunaan GenAI publik di browser managed.

## Scope
- Extension Chrome/Edge (managed deployment) untuk intersepsi prompt submit, paste, dan file upload di domain AI katalog.
- Deteksi konteks akun corporate vs personal.
- Aksi warn/coach (dengan justifikasi), redact, dan block, plus halaman alternatif sanctioned.
- Contract test harian terhadap UI vendor utama.

## Acceptance criteria
- [ ] E2E test di minimal 5 app GenAI teratas dari baseline (tiket 03).
- [ ] Justifikasi user tercatat sebagai event.
- [ ] Extension tidak mengirim raw content ke selain detection-svc internal.
- [ ] Syarat DPIA (tiket 35, R3/R8): justifikasi user dibatasi panjang dan melewati detektor sebelum disimpan; akun personal tanpa forensic capture kecuali DPO menyetujui lain.

## Catatan ADR-0001
Ditunda ke M3+ (DEC-5). Dievaluasi ulang setelah [ASM-5] inventaris SWG/CASB/DLP terverifikasi: lanjut bila vendor tidak punya kapabilitas ini, dibatalkan bila sudah ada (event vendor dikonsumsi lewat tiket 15).
