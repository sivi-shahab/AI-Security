-- Audit log (spec FR-COMP-4, §10.2 retention >= 5 years). Idempotent: applied by audit.Open.
-- Rows are never updated or deleted, so retention is "forever" here; the WORM anchors are the tamper evidence.
CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE IF NOT EXISTS audit.audit_log (
  seq       bigint PRIMARY KEY CHECK (seq > 0),
  tenant_id uuid        NOT NULL,
  ts        timestamptz NOT NULL,
  actor     text        NOT NULL,
  action    text        NOT NULL,
  target    jsonb       NOT NULL,
  prev_hash text        NOT NULL,
  hash      text        NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS audit_log_ts ON audit.audit_log (ts);

CREATE OR REPLACE FUNCTION audit.reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit.audit_log is append-only';
END $$;

-- Blocks the application and its owner role; a superuser could still disable it, which the anchors detect.
CREATE OR REPLACE TRIGGER audit_log_append_only
  BEFORE UPDATE OR DELETE ON audit.audit_log FOR EACH ROW EXECUTE FUNCTION audit.reject_change();
CREATE OR REPLACE TRIGGER audit_log_no_truncate
  BEFORE TRUNCATE ON audit.audit_log FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_change();
