# 01: Keputusan hosting, data residency & build-vs-buy

Status: needs-triage
Type: grilling
Priority: P0
Milestone: M0
Spec: `../spec.md` §18 U3, U4, U7, U11; §19 DEC-5; §10.2

## Konteks
Tiga hal belum diputuskan: lokasi hosting, data residency, dan apakah modul AI di SWG/CASB/DLP yang sudah dimiliki cukup (build vs buy). Ketiganya mengunci arsitektur M1.

## Scope
- Inventaris SWG/CASB/DLP yang sudah dipakai bank beserta kapabilitas modul AI-nya (prompt/response inspection, MCP, shadow AI).
- Putuskan on-prem DC vs cloud region Indonesia (U3) dan konfirmasi tidak ada komponen offshore (U4, POJK 11 Pasal 35).
- Putuskan cakupan build: penuh, atau fokus AI Gateway + MCP Gateway + detektor lokal + compliance (DEC-5).
- Konfirmasi single-tenant internal (ASM-4).

## Acceptance criteria
- [ ] Keputusan tercatat sebagai ADR di `docs/adr/`.
- [ ] Spec §18 (U3, U4, U7, U11) dan §19 diperbarui dengan hasil keputusan.
- [ ] Tiket yang terdampak build-vs-buy diberi catatan (tetap, digabung, atau dibatalkan).
