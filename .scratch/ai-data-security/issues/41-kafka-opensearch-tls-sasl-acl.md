# 41: Kafka/OpenSearch: TLS, SASL/mTLS client, ACL topic per producer

Status: needs-triage
Type: task
Priority: P1
Milestone: M2
Blocked by: 15
Spec: `../spec.md` §10.1 Encryption; `docs/threat-model.md` G2

## Konteks
Threat model (tiket 02) G2: client Kafka belum mengonfigurasi TLS/SASL (catatan tiket 15). Siapa pun di jaringan bisa memproduksi decision event palsu (insiden palsu, atau banjir untuk menyamarkan serangan) atau membaca event. OpenSearch belum diautentikasi dari client.

## Scope
- Konfigurasi TLS + SASL (SCRAM atau mTLS) di producer/consumer (`internal/events`, event-ingest, incident, siem-export).
- ACL topic: hanya PEP yang boleh produce ke `decision_event`, consumer per group.
- Client OpenSearch dengan TLS + auth.

## Acceptance criteria
- [ ] Producer tanpa kredensial ditolak broker (test integrasi).
- [ ] Event dari principal yang bukan PEP ditolak atau ditandai.
- [ ] Koneksi plaintext ke Kafka/OpenSearch gagal di konfigurasi produksi.
