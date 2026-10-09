-- Registered confidential documents (spec §9.1 L3, ticket 37). Idempotent: applied by similarity.Open.
-- Only keyed fingerprints are stored, never the text; content_hmac (tenant pepper) stops double registration.
CREATE SCHEMA IF NOT EXISTS similarity;
CREATE TABLE IF NOT EXISTS similarity.docs (
  id            bigserial   PRIMARY KEY,
  tenant_id     uuid        NOT NULL,
  name          text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  sensitivity   text        NOT NULL CHECK (sensitivity IN ('confidential', 'restricted')),
  content_hmac  text        NOT NULL,
  fingerprints  bigint[]    NOT NULL,
  registered_by text        NOT NULL,
  registered_at timestamptz NOT NULL,
  UNIQUE (tenant_id, content_hmac)
);
