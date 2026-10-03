-- Incidents (spec §4.10, §6). Idempotent: applied by incident.Open.
CREATE SCHEMA IF NOT EXISTS incident;

CREATE TABLE IF NOT EXISTS incident.incidents (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         uuid        NOT NULL,
  dedup_key         text        NOT NULL,
  title             text        NOT NULL,
  state             text        NOT NULL CHECK (state IN ('New','Triaged','Investigating','Contained','Resolved','Closed')),
  severity          text        NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  max_risk          int         NOT NULL,
  event_count       int         NOT NULL,
  first_event_at    timestamptz NOT NULL,
  last_event_at     timestamptz NOT NULL,
  opened_at         timestamptz NOT NULL DEFAULT now(),
  ack_deadline      timestamptz,
  acknowledged_at   timestamptz,
  resolved_at       timestamptz,
  closed_at         timestamptz,
  assignee          text,
  dek_wrapped       bytea       NOT NULL  -- per-incident evidence key, wrapped by the KEK (KMS in production)
);
CREATE INDEX IF NOT EXISTS incidents_dedup ON incident.incidents (tenant_id, dedup_key, last_event_at DESC);
CREATE INDEX IF NOT EXISTS incidents_queue ON incident.incidents (state, severity, opened_at);

-- Redacted evidence: the decision event as it arrived (metadata, hashes, redacted snippet; spec FR-INC-4).
CREATE TABLE IF NOT EXISTS incident.incident_events (
  incident_id uuid        NOT NULL REFERENCES incident.incidents(id),
  event_id    uuid        NOT NULL UNIQUE,  -- an event joins one incident, once (redelivery is a no-op)
  ts          timestamptz NOT NULL,
  risk_score  int         NOT NULL,
  event       jsonb       NOT NULL,
  PRIMARY KEY (incident_id, event_id)
);

-- Raw evidence: only under forensic_capture, encrypted with the incident's DEK, deleted at expires_at (§10.2: 30 days).
CREATE TABLE IF NOT EXISTS incident.evidence (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id uuid        NOT NULL REFERENCES incident.incidents(id),
  kind        text        NOT NULL,
  ciphertext  bytea       NOT NULL,
  sha256      text        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS incident.transitions (
  incident_id uuid        NOT NULL REFERENCES incident.incidents(id),
  at          timestamptz NOT NULL DEFAULT now(),
  actor       text        NOT NULL,
  from_state  text        NOT NULL,
  to_state    text        NOT NULL,
  note        text        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS transitions_incident ON incident.transitions (incident_id, at);
