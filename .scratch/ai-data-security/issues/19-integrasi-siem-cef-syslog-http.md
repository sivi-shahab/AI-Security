# 19: Integrasi SIEM (CEF/syslog, HTTP)

Status: needs-triage
Type: task
Priority: P0
Milestone: M1
Blocked by: 15
Spec: `../spec.md` §11; §12.3 Security telemetry

## Konteks
SOC bank bekerja dari SIEM yang sudah ada.

## Scope
- Export event dan incident ke CEF/syslog dan HTTP (HEC/Sentinel/Elastic).
- Security telemetry platform: perubahan policy, unmask, kill switch, dan kegagalan signature bundle.
- Retry + dead-letter queue.

## Acceptance criteria
- [ ] Test integrasi dengan minimal 1 SIEM target bank.
- [ ] Tidak ada raw content di payload export.
