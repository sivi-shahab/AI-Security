-- Agent registry (spec §4.8 FR-AGT-1/2, §6 AGENT). Idempotent: applied by agents.Open.
CREATE SCHEMA IF NOT EXISTS agents;

CREATE TABLE IF NOT EXISTS agents.agents (
  agent_id       text PRIMARY KEY CHECK (agent_id ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
  name           text        NOT NULL,
  owner          text,                    -- identity userName; none (or inactive) = quarantined
  business_unit  text        NOT NULL,    -- ABAC: agent owners act within their unit
  purpose        text        NOT NULL,
  model          text,
  framework      text,
  environment    text        NOT NULL CHECK (environment IN ('dev', 'staging', 'prod')),
  identity_type  text        NOT NULL CHECK (identity_type IN ('spiffe', 'oidc_client', 'managed_identity')),
  identity_ref   text        NOT NULL UNIQUE,  -- one workload identity, one agent: no sharing
  tools          jsonb       NOT NULL DEFAULT '[]',  -- allow-list: [{name, risk, scopes}]
  data_scopes    text[]      NOT NULL DEFAULT '{}',
  risk_tier      text        NOT NULL CHECK (risk_tier IN ('low', 'medium', 'high', 'critical')),
  status         text        NOT NULL CHECK (status IN ('active', 'quarantined', 'suspended', 'retired')),
  status_reason  text,
  created_by     text        NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_by     text        NOT NULL,
  updated_at     timestamptz NOT NULL DEFAULT now()
);

-- Shadow agents: seen in decision events (MCP traffic) or OAuth grants, not registered (FR-AGT-1 review queue).
CREATE TABLE IF NOT EXISTS agents.discovered (
  agent_id    text PRIMARY KEY,
  source      text        NOT NULL CHECK (source IN ('mcp_traffic', 'oauth_grant', 'endpoint')),
  state       text        NOT NULL CHECK (state IN ('pending', 'registered', 'dismissed')),
  first_seen  timestamptz NOT NULL,
  last_seen   timestamptz NOT NULL,
  events      bigint      NOT NULL DEFAULT 0,  -- approximate: redelivered events count again
  decided_by  text,
  decided_at  timestamptz,
  note        text
);

-- MCP tool definitions as tools/list returns them (FR-AGT-3, ticket 29). hash is the latest definition seen,
-- approved_hash the pinned one: a tool is callable only while they match and status is approved.
CREATE TABLE IF NOT EXISTS agents.mcp_tools (
  server         text        NOT NULL,
  name           text        NOT NULL,
  hash           text        NOT NULL,
  definition     jsonb       NOT NULL,
  risk           text        NOT NULL CHECK (risk IN ('low', 'medium', 'high')),
  score          real        NOT NULL,
  signals        text[]      NOT NULL DEFAULT '{}',
  status         text        NOT NULL CHECK (status IN ('approved', 'under_review', 'rejected')),
  approved_hash  text,
  first_seen     timestamptz NOT NULL,
  last_seen      timestamptz NOT NULL,
  decided_by     text,
  decided_at     timestamptz,
  note           text,
  PRIMARY KEY (server, name)
);

-- HITL approvals (FR-AGT-6, ticket 30). The gateway asks for one per (agent, server, tool, args digest); the raw
-- arguments never leave it, the preview has secrets and card data redacted. Single use, expires at expires_at.
CREATE TABLE IF NOT EXISTS agents.approvals (
  id            text        PRIMARY KEY,
  agent_id      text        NOT NULL,
  server        text        NOT NULL,
  tool          text        NOT NULL,
  args_digest   text        NOT NULL,
  preview       jsonb       NOT NULL,
  reason_codes  text[]      NOT NULL DEFAULT '{}',
  trace_id      text,
  state         text        NOT NULL CHECK (state IN ('pending', 'approved', 'rejected', 'expired', 'used')),
  requested_at  timestamptz NOT NULL,
  expires_at    timestamptz NOT NULL,
  decided_by    text,
  decided_at    timestamptz,
  note          text,
  used_at       timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS approvals_open ON agents.approvals (agent_id, server, tool, args_digest)
  WHERE state IN ('pending', 'approved');

-- Kill switches (FR-AGT-7): at most one active per scope and target; lifting keeps the row for the record.
CREATE TABLE IF NOT EXISTS agents.kills (
  id          bigserial   PRIMARY KEY,
  scope       text        NOT NULL CHECK (scope IN ('agent', 'tool', 'app', 'global')),
  target      text        NOT NULL,  -- agent_id, tool name, app_id; '' for global
  reason      text        NOT NULL,
  created_by  text        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  lifted_by   text,
  lifted_at   timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS kills_active ON agents.kills (scope, target) WHERE lifted_at IS NULL;
