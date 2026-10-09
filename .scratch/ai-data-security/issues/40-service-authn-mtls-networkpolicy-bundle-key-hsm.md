# 40: Service-to-service authN, NetworkPolicy default-deny, kunci bundle di KMS/HSM

Status: needs-triage
Type: task
Priority: P1
Milestone: M2
Spec: `../spec.md` §10.1 AuthN (SPIFFE/mTLS), Self-protection; `docs/threat-model.md` G1

## Konteks
Threat model (tiket 02) G1: detection-svc dan model-inference menerima request dari pod mana pun di cluster (oracle untuk mengakali detektor). `GET /bundles/aisec.tar.gz` public, sehingga data katalog, registry agent, dan exception terbaca dari jaringan. Kunci tanda tangan bundle berupa file Secret, bukan KMS/HSM.

## Scope
- mTLS antar-service (SPIFFE/SVID via mesh atau cert-manager), atau minimal NetworkPolicy default-deny di namespace `aisec` dengan allow eksplisit per alur §5.2.
- `/bundles` hanya untuk OPA sidecar (identitas workload).
- Tanda tangan bundle lewat KMS/HSM; kunci privat tidak pernah berupa file di pod.

## Acceptance criteria
- [ ] Pod tanpa identitas yang berhak ditolak saat memanggil detection-svc, model-inference, dan `/bundles` (test).
- [ ] NetworkPolicy default-deny aktif; alur §5.2 tetap lulus smoke test.
- [ ] Rotasi kunci bundle tanpa downtime terdokumentasi.
