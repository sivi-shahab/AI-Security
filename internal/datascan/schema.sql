-- Data-at-rest discovery (spec §4.3 FR-DATA, §6 DATA_SOURCE / DATA_ASSET / CLASSIFICATION_RESULT / ACL_ENTRY).
-- No raw content: an asset is its id, a path hash, tags, findings and grants. Idempotent: applied by datascan.Open.
CREATE SCHEMA IF NOT EXISTS data;

CREATE TABLE IF NOT EXISTS data.containers (
  source_id     text        NOT NULL,
  container_id  text        NOT NULL,
  name          text        NOT NULL,
  kind          text        NOT NULL,
  cursor        text        NOT NULL DEFAULT '',  -- change-feed position; '' = next pass enumerates everything
  mode          text        NOT NULL DEFAULT 'sample' CHECK (mode IN ('sample', 'full')),
  items         bigint      NOT NULL DEFAULT 0,   -- files seen in the last complete pass
  sampled       bigint      NOT NULL DEFAULT 0,   -- files whose content was classified
  sensitive     bigint      NOT NULL DEFAULT 0,   -- of those, confidential or restricted
  last_scan     timestamptz,
  PRIMARY KEY (source_id, container_id)
);

CREATE TABLE IF NOT EXISTS data.assets (
  id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id        text        NOT NULL,
  container_id     text        NOT NULL,
  external_id      text        NOT NULL,
  path_hash        text        NOT NULL,          -- HMAC of the path (tenant pepper)
  content_tag      text        NOT NULL,          -- unchanged tag = content not read again
  size             bigint      NOT NULL,
  label            text,                          -- external sensitivity label id (Purview), FR-CLS-6
  sensitivity      text        NOT NULL CHECK (sensitivity IN ('public', 'internal', 'confidential', 'restricted')),
  exposure_score   int         NOT NULL CHECK (exposure_score BETWEEN 0 AND 100),
  flags            text[]      NOT NULL DEFAULT '{}',
  content_scanned  boolean     NOT NULL DEFAULT false,
  scan_note        text,                          -- why content was not (fully) classified
  modified_at      timestamptz,
  scanned_at       timestamptz NOT NULL,
  deleted_at       timestamptz,
  UNIQUE (source_id, external_id)
);
CREATE INDEX IF NOT EXISTS assets_exposure ON data.assets (exposure_score DESC) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS data.classifications (
  asset_id       uuid NOT NULL REFERENCES data.assets (id) ON DELETE CASCADE,
  class          text NOT NULL,
  count          int  NOT NULL,
  confidence     real NOT NULL,
  model_version  text NOT NULL,
  PRIMARY KEY (asset_id, class)
);

CREATE TABLE IF NOT EXISTS data.acl_entries (
  asset_id      uuid    NOT NULL REFERENCES data.assets (id) ON DELETE CASCADE,
  grantee_kind  text    NOT NULL,
  grantee_ref   text    NOT NULL,   -- UPN or group name, kept for remediation (ticket 33); '' for anyone links
  permission    text    NOT NULL,
  external      boolean NOT NULL
);
CREATE INDEX IF NOT EXISTS acl_entries_asset ON data.acl_entries (asset_id);

-- Third-party OAuth grants (ticket 32): which apps users let into bank data, and whether they are AI apps.
CREATE TABLE IF NOT EXISTS data.oauth_grants (
  source      text        NOT NULL,
  client_id   text        NOT NULL,
  app_name    text        NOT NULL,
  scopes      text[]      NOT NULL DEFAULT '{}',
  ai          boolean     NOT NULL,
  first_seen  timestamptz NOT NULL,
  last_seen   timestamptz NOT NULL,
  PRIMARY KEY (source, client_id)
);
CREATE TABLE IF NOT EXISTS data.oauth_grant_users (
  source     text NOT NULL,
  client_id  text NOT NULL,
  user_hash  text NOT NULL,  -- HMAC of the e-mail (tenant pepper)
  PRIMARY KEY (source, client_id, user_hash)
);
