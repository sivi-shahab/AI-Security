# 26: Incident lanjut: korelasi, breach timer UU PDP, SOAR/ITSM

Status: needs-triage
Type: task
Priority: P1
Milestone: M2
Blocked by: 18, 19
Spec: `../spec.md` §4.10 FR-INC-1, FR-INC-5, FR-INC-6; §11

## Konteks
Melengkapi incident untuk kebutuhan regulasi dan otomasi.

## Scope
- Korelasi berbasis `trace_id`/sesi agent ke satu incident rantai.
- Breach workflow: timer 3×24 jam + draft laporan (data terungkap, kapan/bagaimana, penanganan) sesuai Pasal 46.
- Containment actions API.
- Integrasi ServiceNow/Jira SM + webhook SOAR.

## Acceptance criteria
- [ ] Draft laporan breach dapat dihasilkan ≤ 24 jam dari deteksi (metrik §1.5).
- [ ] Alert eskalasi saat sisa timer < 24 jam.
- [ ] Test integrasi ITSM.
