# 12: Policy lifecycle: versi, 4-eyes, simulasi, rollback, exception

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 11, 15
Spec: `../spec.md` §4.7 FR-POL-5..7; §8.3

## Konteks
Admin DLP harus bisa mengubah kebijakan dengan aman.

## Scope
- State `draft → simulated → pending_approval → active → retired`; author ≠ approver.
- Simulasi terhadap event 7–30 hari + corpus, dengan diff keputusan (`POST /policies/{id}/simulate`).
- Mode monitor-only per rule.
- Rollback ke versi sebelumnya dalam 1 aksi.
- Exception dengan scope, approver, dan kedaluwarsa wajib (default maks 90 hari), notifikasi 7 hari sebelum kedaluwarsa.

## Acceptance criteria
- [x] Propagasi publish/rollback ke semua PEP ≤ 60 s p99. *(`TestPropagation`: 2 replica + OPA SDK (plugin bundle yang sama dengan sidecar) long-poll ke replica B; 22 release (publish, exception on/off, retire): p50 0,76 s, p99 0,80 s.)*
- [x] Publish tanpa approver kedua ditolak. *(Author = approver → 403, juga beda huruf besar/kecil; exception: requester = approver ditolak.)*
- [x] Exception tanpa `expires_at` ditolak. *(Juga: sudah lewat, > 90 hari, scope kosong/tak dikenal, rule tak ada di release aktif, tanpa alasan.)*
- [x] Semua transisi tercatat di audit log. *(Create, edit, simulate, simulate.done, submit, reject, approve, rollback, retire, exception request/approve/revoke/expire/expiring; dalam transaksi yang sama.)*

## Keputusan
- Policy = rule set dalam DSL engine (bukan Rego mentah). Versi: `draft → simulated → pending_approval → active → retired`; edit setelah simulasi mengembalikan ke draft; submit hanya dari `simulated`; reject kembali ke draft. Satu versi aktif per policy (unique index).
- **Release**: setiap approve/rollback/retire/exception mengambil snapshot semua rule aktif + exception aktif sebagai release bernomor (`policy_version = release-N` di keputusan dan event). Release divalidasi engine sebelum ada (id rule bentrok antar-policy, op tidak dikenal → seluruh perubahan batal).
- Setiap replica control-plane membangun bundle dari release terbaru: `LISTEN/NOTIFY` Postgres + poll 15 s. Revisi = hash konten, jadi semua replica memberi ETag yang sama. Metrik `policy_release_current` + alert bila replica berbeda > 1 menit.
- Approve/reject/rollback/retire/keputusan exception = `policy.publish` (sensitif: step-up + justifikasi). Rollback memulihkan versi yang sebelumnya disetujui, tanpa approver kedua.
- Simulasi (`POST /policies/{id}/simulate` → 202, `GET /simulations/{id}`): event dari OpenSearch (default 7 hari, maks 30, cap 100k) dievaluasi dengan komposisi aktif vs kandidat → diff `allow→block` dst + 20 sampel; corpus berlabel (`policy/corpus/*.jsonl`, 9 kasus template) → regresi. Untuk replay, `decision_event` v1 ditambah field metadata input PDP (sanction, region, sensitivity, skor, atribut principal/agent); event tanpa metadata itu dihitung tapi tidak di-replay.
- Exception: scope `principal_id|group|app_id|agent_id` (AND), wajib `expires_at` ≤ 90 hari, 4-eyes, masuk bundle; Rego juga memeriksa kedaluwarsa saat keputusan. Sweep per jam: tandai expired + release, notifikasi 7 hari sebelum = audit `policy.exception.expiring` (diteruskan ke SIEM, ticket 19) + metrik/alert.
- Monitor-only per rule sudah ada di engine (ticket 11); simulasi melaporkannya lewat diff.
- Output PDP menambah `exempted_rules`.

## Hasil verifikasi lokal (2026-10-03)
- `opa test` 37/37, `opa check --strict`; `go test -race ./...` dengan semua service integrasi; golangci-lint bersih; image control-plane ter-build.

## Sisa / follow-up
- Exception self-service end user (`self.request`) dan scope user dengan email (butuh pepper HMAC di control-plane): belum.
- Simulasi berjalan di replica yang menerima request; jika replica mati, status tetap `running` (ponytail di kode).
- Notifikasi langsung ke pemilik (email/Slack) menunggu kanal notifikasi; sekarang lewat audit/SIEM + alert.
- PEP harus mengisi field metadata event baru (ticket 13).
