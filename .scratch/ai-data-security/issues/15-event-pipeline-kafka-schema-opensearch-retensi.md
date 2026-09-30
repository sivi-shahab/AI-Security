# 15: Event pipeline: Kafka schema, OpenSearch, retensi

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 05
Spec: `../spec.md` §5.1 Analytics; §6 catatan; §10.2; §12.3

## Konteks
Semua PEP menulis `decision_event` ke satu pipeline.

## Scope
- Skema event berversi di schema registry (metadata + HMAC hash + snippet redacted ≤ 200 karakter).
- Consumer ke OpenSearch (index per tenant bila diperlukan) + partisi harian + TTL (90 hari hot, 400 hari total).
- Propagasi `trace_id` dari PEP.
- Validator pipeline yang menolak event berisi field konten mentah.

## Acceptance criteria
- [ ] Event muncul di search ≤ 60 s p95.
- [ ] Test privasi: event dengan raw content ditolak dan dihitung di metrik.
- [ ] Metrik `kafka_consumer_lag` tersedia.
