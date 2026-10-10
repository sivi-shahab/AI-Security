# 14: AI Gateway: inspeksi response streaming (SSE)

Status: needs-triage
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
- [ ] Test: NIK yang terpotong di 2 chunk tetap ter-redact.
- [ ] Test: block di tengah stream → klien SDK menerima akhir stream yang valid.
- [ ] Overhead per window p95 ≤ 20 ms.

## Catatan dari tiket 13
- `internal/aigw` saat ini menolak `stream: true` dengan 400 format provider. Inspeksi response non-streaming (`call.enforce` arah `response`) dan root teks per endpoint sudah ada untuk dipakai ulang per window.
