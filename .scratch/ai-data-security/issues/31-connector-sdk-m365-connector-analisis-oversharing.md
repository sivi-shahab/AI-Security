# 31: Connector SDK + M365 connector + analisis oversharing

Status: needs-triage
Type: task
Priority: P1
Milestone: M3
Blocked by: 06, 08, 15
Spec: `../spec.md` §4.3 FR-DATA-1..5; §4.4 FR-CLS-5, FR-CLS-6; §11

## Konteks
Posture data-at-rest yang dikonsumsi Copilot/RAG.

## Scope
- Kontrak Connector SDK (`list_containers`, `list_items`, `get_item`, `get_acl`, `apply_remediation`) + checkpoint cursor.
- M365 connector (SharePoint/OneDrive/Teams) dengan delta query + baca label Purview.
- File extraction service tersandbox (Tika) dengan batas zip bomb.
- Sampling adaptif + analisis ACL: link anonim, share eksternal, grup luas, izin yatim.
- Output `DATA_ASSET`, `CLASSIFICATION_RESULT`, `exposure_score` tanpa raw content.

## Acceptance criteria
- [ ] Scan incremental tidak mengulang item yang tidak berubah.
- [ ] Fuzz test parser file.
- [ ] Rate limit Graph API dihormati (backoff).
