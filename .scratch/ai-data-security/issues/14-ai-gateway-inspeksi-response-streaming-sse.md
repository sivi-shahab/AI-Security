# 14: AI Gateway: inspeksi response streaming (SSE)

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 13
Spec: `../spec.md` §4.6 FR-DLP-2; §7.1

## Konteks
Mayoritas aplikasi chat memakai streaming, dan response bisa membocorkan data atau system prompt.

## Scope
- Sliding window (default 256 token) + look-behind untuk entitas yang terpotong antar-chunk.
- Redact per window. Block di tengah stream memutus stream dan mengirim event penutup yang valid per provider.
- Canary token opsional di system prompt app terdaftar + deteksi n-gram overlap system prompt (FR-PSEC-5).

## Acceptance criteria
- [x] Test: NIK yang terpotong di 2 chunk tetap ter-redact. *(`TestStreamEntitySplit`, OpenAI chat / Anthropic / Gemini: NIK dan PAN yang terpotong antar-delta dan antar-window (window diperkecil ke 40 byte) ter-redact; sisa jawaban identik dan berurutan; event penutup provider tetap di akhir. Response default tidak me-redact NIK, jadi test memakai rule bank tambahan; PAN memakai template `tpl.pci-pan-redact`.)*
- [x] Test: block di tengah stream → klien SDK menerima akhir stream yang valid. *(`TestStreamBlockMidStream` per provider, plus `testdata/sdk_smoke.py` dengan SDK resmi: OpenAI → chunk `finish_reason: content_filter` + `[DONE]`; Anthropic → semua block ditutup, block teks pemberitahuan, `message_delta stop_reason: refusal`, `message_stop` (`get_final_message()` berhasil); Gemini → `finishReason: SAFETY`. Canary tidak pernah sampai ke klien, termasuk separuhnya.)*
- [x] Overhead per window p95 ≤ 20 ms. *(`TestStreamWindowOverhead`: scan + keputusan policy asli + rilis satu window 256 token, 300 window: p50 4,2 ms, p95 7,3 ms. Saat seluruh suite paralel di satu mesin, p95 naik ke ±29 ms karena contention CPU, sehingga test ini di-skip pada `-short` seperti `TestOverhead`.)*

## Catatan dari tiket 13
- `internal/aigw` saat ini menolak `stream: true` dengan 400 format provider. Inspeksi response non-streaming (`call.enforce` arah `response`) dan root teks per endpoint sudah ada untuk dipakai ulang per window.

## Keputusan
- **Window per kanal teks** (choice/tool call OpenAI, content block Anthropic, candidate Gemini), default 256 token (1.024 byte). Ekor 128 byte ditahan sampai teks berikutnya datang, sehingga entitas yang terpotong antar-chunk utuh saat dipindai; titik rilis tidak pernah jatuh di tengah temuan; 64 byte teks yang sudah terkirim ikut dipindai sebagai konteks kata kunci. Setiap window diputuskan PDP (arah `response`).
- **Gateway menyintesis event delta** dalam format provider untuk teks yang dirilis. Event struktural diteruskan sesuai urutan: event pembuka (message_start, role, tool call baru) setelah teks sebelumnya dirilis; event penutup (finish, stop, usage) setelah teks di event itu. Teks di dalam event struktural (function call Gemini, dll.) diinspeksi utuh.
- **Satu event keputusan per stream** (bukan per window): keputusan paling ketat, temuan digabung, HMAC seluruh teks, snippet pertama. ID-nya dikutip di pemberitahuan block.
- **FR-PSEC-5:** `canary: true` per app menanam penanda rahasia per app (turunan pepper) di system prompt; response yang memuatnya → `exfil_score` 1. Tanpa canary, overlap 8-gram kata dengan system prompt (8 shingle ≈ 15 kata berturut-turut = skor 1). Rule baru `tpl.system-prompt-leak`: response dengan `exfil_score` ≥ 0,8 → block. Berlaku juga untuk response non-streaming.
- **Gemini** streaming lewat `:streamGenerateContent?alt=sse`. **Responses API OpenAI** streaming masih ditolak (400): event snapshot-nya (`output_text.done`, `response.completed`) memuat ulang seluruh teks dan perlu ditulis ulang tersendiri.
- PDP mati di tengah stream: app `fail_open` lanjut dan tercatat, app `fail_closed` dihentikan dengan penutup block.

## Sisa
- Streaming Responses API.
- Redaksi di dalam `partial_json` (argumen tool) bisa menghasilkan JSON tidak valid bila nilai yang diredaksi berupa angka tanpa tanda kutip.
- Window 256 token menunda teks pertama ±1 KB. Bila UX chat terasa lambat, jadikan konfigurasi per app.
