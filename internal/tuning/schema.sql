-- Per-tenant detector tuning (spec §9.3, §9.4, ticket 38). Idempotent: applied by tuning.Open.
CREATE SCHEMA IF NOT EXISTS tuning;

-- Explicit opt-in to tenant model training (DPO). Append-only: the latest row is the state.
CREATE TABLE IF NOT EXISTS tuning.optin (
  tenant_id uuid        NOT NULL,
  enabled   boolean     NOT NULL,
  note      text        NOT NULL,
  actor     text        NOT NULL,
  at        timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS optin_latest ON tuning.optin (tenant_id, at DESC);

-- Triage labels: is this class in this incident event a real finding? The event itself (redacted snippet and
-- metadata) stays in incident.incident_events.
CREATE TABLE IF NOT EXISTS tuning.labels (
  tenant_id  uuid        NOT NULL,
  event_id   uuid        NOT NULL,
  class      text        NOT NULL,
  tp         boolean     NOT NULL,
  labeled_by text        NOT NULL,
  labeled_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, event_id, class)
);

-- Model versions. weights never leave the tenant: every read filters tenant_id, and feature hashes are keyed with
-- the tenant pepper.
CREATE TABLE IF NOT EXISTS tuning.models (
  tenant_id  uuid        NOT NULL,
  version    int         NOT NULL,
  stage      text        NOT NULL CHECK (stage IN ('rejected', 'candidate', 'shadow', 'canary', 'active', 'retired')),
  weights    jsonb       NOT NULL,
  gate       jsonb       NOT NULL,
  labels     int         NOT NULL,  -- training labels used
  trained_by text        NOT NULL,
  trained_at timestamptz NOT NULL,
  changed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, version)
);
-- At most one model per live stage.
CREATE UNIQUE INDEX IF NOT EXISTS models_live ON tuning.models (tenant_id, stage) WHERE stage IN ('shadow', 'canary', 'active');

-- Frozen holdout (spec §9.4: eval set frozen per quarter): the holdout labels as they stood at the quarter's first
-- training run. The gate scores every candidate of the quarter against it, so relabelling cannot move the yardstick.
CREATE TABLE IF NOT EXISTS tuning.holdout (
  tenant_id uuid    NOT NULL,
  quarter   text    NOT NULL,  -- e.g. 2026Q4
  event_id  uuid    NOT NULL,
  class     text    NOT NULL,
  tp        boolean NOT NULL,
  PRIMARY KEY (tenant_id, quarter, event_id, class)
);
