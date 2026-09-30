# 34: Compliance module: framework library, evidence, report

Status: needs-triage
Type: task
Priority: P1
Milestone: M3
Blocked by: 07, 18
Spec: `../spec.md` §4.11 FR-COMP-1..3; §14

## Konteks
Bukti kepatuhan untuk OJK, UU PDP, dan ISO 42001.

## Scope
- Framework library berversi (OWASP LLM/ASI, NIST AI RMF/600-1, ISO 42001, UU PDP + PP 33/2026, POJK 11, Panduan AI OJK).
- Mapping kontrol ↔ requirement; verifikasi nomor subkategori/klausul oleh tim compliance.
- Evidence otomatis dari konfigurasi, policy aktif, statistik enforcement, dan hasil test.
- Riwayat status kontrol + export per periode audit.
- AI inventory/register untuk kebutuhan OJK/ISO 42001.

## Acceptance criteria
- [ ] Mapping §14 terverifikasi terhadap teks resmi.
- [ ] Export laporan untuk satu periode audit sampel.
- [ ] Perubahan versi framework tidak menghapus riwayat lama.
