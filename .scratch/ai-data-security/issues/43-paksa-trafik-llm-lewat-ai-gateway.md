# 43: Paksa trafik LLM lewat AI gateway (egress + deteksi bypass)

Status: needs-triage
Type: task
Priority: P1
Milestone: M2
Blocked by: 13
Spec: `../spec.md` §5.4; `docs/threat-model.md` §4.1, G4

## Konteks
Threat model (tiket 02) G4: tanpa aturan egress, AI gateway bersifat opsional. App bisa memanggil provider LLM langsung dengan key pribadi developer.

## Scope
- Aturan egress (firewall/SWG, dikelola tim jaringan bank) yang mengizinkan domain API provider LLM di katalog hanya dari IP egress AI gateway. Repo menyediakan daftar domain dari katalog (`hosting_region`, kategori API).
- Sinyal posture: trafik langsung dari subnet server ke domain API provider (dari log SWG/DNS, tiket 03) → event + temuan posture.

## Acceptance criteria
- [ ] Ekspor daftar domain API provider dari katalog, dengan test.
- [ ] Trafik langsung ke provider di log sintetis menghasilkan temuan posture "gateway bypass".
- [ ] Runbook aturan egress diserahkan ke tim jaringan.
