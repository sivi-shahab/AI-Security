# 18: Incident management dasar

Status: needs-gitlab-run
Type: task
Priority: P0
Milestone: M1
Blocked by: 15, 17
Spec: `../spec.md` §4.10 FR-INC-1..4, FR-INC-7; §8.5

## Konteks
SOC butuh tempat triage.

## Scope
- State machine (FR-INC-3) dan severity dari skor.
- Dedup `(principal, destination, class, policy_id)` dalam window 30 menit.
- Evidence redacted; raw hanya jika `forensic_capture` aktif (terenkripsi per incident, unmask dengan justifikasi).
- SLA timer acknowledge (critical ≤ 15 menit, high ≤ 1 jam).
- API incidents + transition.

## Acceptance criteria
- [x] Test transisi state valid dan invalid. *(Semua 36 pasangan state; edge berlabel (duplicate, false positive, reopen) wajib note; lewat API: 409 untuk transisi invalid, 403 tanpa `incident.write`.)*
- [x] Test dedup window. *(Postgres: ≤ 30 menit dari event terakhir bergabung, 31 menit buka incident baru; principal/class lain terpisah; incident Resolved tidak menerima event; redelivery no-op; risk < 40 diabaikan.)*
- [x] Akses unmask tanpa permission/justifikasi ditolak dan tercatat. *(403 + entri `evidence.unmask.denied` di audit log; akses sah juga tercatat sebelum dekripsi; rantai audit tetap terverifikasi.)*

## Keputusan
- Modul `internal/incident` di control-plane (DEC-3), schema Postgres `incident`, consumer group `incident` sendiri di topic decision_event. Validasi event dipakai bersama event-ingest (`events.Decoder`).
- Incident hanya dari event `risk_score ≥ 40`. Severity = FR-INC-2 dari risk tertinggi, naik otomatis saat event lebih berisiko masuk, naik manual lewat API, tidak bisa turun.
- Dedup key = principal (HMAC), app, set class, set matched rule (pengganti `policy_id` yang konstan). Window geser: event masuk bila dalam 30 menit dari event incident yang masih terbuka. Advisory lock per key mencegah incident kembar.
- SLA ack: critical 15 menit, high 1 jam, dihitung dari pembukaan atau eskalasi (diambil yang lebih ketat). Ack = keluar dari New. Gauge `incident_ack_overdue` + alert.
- Evidence: event redacted disimpan apa adanya. Raw (hanya forensic_capture) dienkripsi AES-256-GCM dengan DEK per incident yang dibungkus KEK, terikat ke incident/evidence id (AAD), dihapus setelah 30 hari.
- Transisi dan perubahan severity ditulis ke audit log dalam transaksi yang sama (`audit.AppendTx`). Unmask diaudit sebelum plaintext dikembalikan; bila audit gagal, tidak ada plaintext.
- Auth sementara: header dari proxy terautentikasi, hanya bila `AUTH_MODE=trusted-proxy`; mode lain menolak semua request.

## Hasil verifikasi lokal (2026-10-03)
- Unit + integrasi Postgres lulus dengan `-race`; seluruh suite (audit, events, ingest, policysvc) ikut lulus; golangci-lint dan trivy config bersih.
- E2E image control-plane + Kafka + Karapace + Postgres: 3 event (risk 72, 95, 50) → satu incident critical, 3 event, ack deadline; event risk 10 diabaikan.

## Sisa / follow-up
- ~~SSO/RBAC dan re-auth untuk `evidence.unmask` (ticket 06) menggantikan header proxy.~~ Selesai di ticket 06; raw evidence sekarang di `…/evidence/{eid}/raw`.
- Belum ada pemanggil `AddRawEvidence`: PEP dengan forensic_capture (ticket 13). Pindah ciphertext ke object storage bila volumenya besar.
- KEK dari KMS/HSM; Secret `control-plane` dan `incident-kek` di-provision di luar git.
- Topic Kafka dibuat oleh tim platform (client tidak auto-create).
- MTTD/MTTR, containment actions (FR-INC-5), korelasi `trace_id`: ticket 26.

## Out of scope
Korelasi lintas sesi agent, breach timer, dan SOAR/ITSM (tiket 26).
