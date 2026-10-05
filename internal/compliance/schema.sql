-- Compliance module (spec §4.11 FR-COMP-1..3, §14; ticket 34). Everything here is append-only: a new framework
-- version, a re-verification or a status change adds rows; nothing is updated or deleted, so any past audit
-- period can be reported as it was. Idempotent: applied by compliance.Open.
CREATE SCHEMA IF NOT EXISTS compliance;

-- Framework library versions, kept whole (requirement ids and short titles; no licensed text).
CREATE TABLE IF NOT EXISTS compliance.frameworks (
  framework    text        NOT NULL,
  version      text        NOT NULL,
  doc          jsonb       NOT NULL,
  sha256       text        NOT NULL,
  imported_at  timestamptz NOT NULL,
  PRIMARY KEY (framework, version)
);

-- Control ↔ requirement, per framework version, with the desk research behind it (not a sign-off).
CREATE TABLE IF NOT EXISTS compliance.mappings (
  framework    text  NOT NULL,
  version      text  NOT NULL,
  control_id   text  NOT NULL,
  requirement  text  NOT NULL,
  research     jsonb NOT NULL,  -- {verdict, source, note}
  PRIMARY KEY (framework, version, control_id, requirement),
  FOREIGN KEY (framework, version) REFERENCES compliance.frameworks (framework, version)
);

-- Compliance team sign-offs against the official text; the latest per mapping counts.
CREATE TABLE IF NOT EXISTS compliance.verifications (
  id           bigserial   PRIMARY KEY,
  framework    text        NOT NULL,
  version      text        NOT NULL,
  control_id   text        NOT NULL,
  requirement  text        NOT NULL,
  status       text        NOT NULL CHECK (status IN ('verified', 'rejected')),
  source       text        NOT NULL,  -- where in the official text (URL, pasal/ayat, clause)
  note         text,
  verified_by  text        NOT NULL,
  verified_at  timestamptz NOT NULL,
  FOREIGN KEY (framework, version, control_id, requirement) REFERENCES compliance.mappings (framework, version, control_id, requirement)
);

-- Evidence, automatic (collectors) or attached by the compliance team.
CREATE TABLE IF NOT EXISTS compliance.evidence (
  id            bigserial   PRIMARY KEY,
  control_id    text        NOT NULL,
  kind          text        NOT NULL CHECK (kind IN ('automatic', 'attachment')),
  status        text        NOT NULL CHECK (status IN ('pass', 'partial', 'fail', 'unknown')),
  summary       jsonb       NOT NULL,
  sha256        text        NOT NULL,  -- of the canonical summary (and the attachment, for attachments)
  collected_by  text        NOT NULL,
  collected_at  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_control ON compliance.evidence (control_id, collected_at);

-- Control status history: a row when a control's status (or its reasons) changes.
CREATE TABLE IF NOT EXISTS compliance.control_status (
  id           bigserial   PRIMARY KEY,
  control_id   text        NOT NULL,
  status       text        NOT NULL CHECK (status IN ('pass', 'partial', 'fail', 'unknown')),
  reasons      text[]      NOT NULL,
  evidence_id  bigint      NOT NULL REFERENCES compliance.evidence (id),
  at           timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS control_status_at ON compliance.control_status (control_id, at);

CREATE OR REPLACE FUNCTION compliance.reject_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'compliance history is append-only';
END $$;
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['frameworks', 'mappings', 'verifications', 'evidence', 'control_status'] LOOP
    EXECUTE format('CREATE OR REPLACE TRIGGER %I_append_only BEFORE UPDATE OR DELETE ON compliance.%I FOR EACH ROW EXECUTE FUNCTION compliance.reject_change()', t, t);
  END LOOP;
END $$;
