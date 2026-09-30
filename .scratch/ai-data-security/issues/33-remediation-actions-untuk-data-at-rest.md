# 33: Remediation actions untuk data-at-rest

Status: needs-triage
Type: task
Priority: P1
Milestone: M3
Blocked by: 31
Spec: `../spec.md` §4.3 FR-DATA-6; §4.6 quarantine/remediate

## Konteks
Menutup oversharing yang ditemukan.

## Scope
- Aksi: cabut link anonim, hapus grup luas, terapkan label, quarantine.
- Aksi hanya jalan dengan approval sesuai policy.
- Dry-run + audit log + kemampuan undo bila API mendukung.

## Acceptance criteria
- [ ] Test dry-run vs eksekusi.
- [ ] Aksi tanpa approval ditolak.
