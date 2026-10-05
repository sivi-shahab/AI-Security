-- Data-at-rest remediation (spec FR-DATA-6, ticket 33). Idempotent: applied by remediate.Open.
-- A request is dry-run by the connector worker (plan), approved by someone else, re-planned and executed only if
-- the plan still holds. Undo is a remediation of its own (undo_of), approved the same way.
CREATE TABLE IF NOT EXISTS data.remediations (
  id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id      uuid        NOT NULL REFERENCES data.assets (id),
  action        jsonb       NOT NULL,           -- connector.Action; {"kind": "undo"} for an undo
  undo_of       uuid        REFERENCES data.remediations (id),
  state         text        NOT NULL CHECK (state IN ('requested', 'planned', 'approved', 'rejected', 'expired',
                                                      'stale', 'done', 'failed', 'nothing_to_do', 'undone')),
  plan          text[],                         -- dry-run steps the approver approves
  result        text[],                         -- steps executed
  undo          jsonb,                          -- the connector's undo data (null: not restorable)
  error         text,
  note          text,
  requested_by  text        NOT NULL,
  requested_at  timestamptz NOT NULL,
  planned_at    timestamptz,
  decided_by    text,
  decided_at    timestamptz,
  decision_note text,
  executed_at   timestamptz
);
CREATE INDEX IF NOT EXISTS remediations_work ON data.remediations (state) WHERE state IN ('requested', 'approved');
-- One open request per asset and action: the same fix is not queued twice.
CREATE UNIQUE INDEX IF NOT EXISTS remediations_open ON data.remediations (asset_id, action)
  WHERE state IN ('requested', 'planned', 'approved');
