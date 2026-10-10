CREATE SCHEMA IF NOT EXISTS tokvault;

-- The tenant's FF1 key, wrapped under the vault KEK (AES-256-GCM, aad = tenant id).
CREATE TABLE IF NOT EXISTS tokvault.keys (
  tenant_id  uuid PRIMARY KEY,
  wrapped    bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Issued tokens. No plaintext: a token decrypts with the key, the row says it was issued and until when.
CREATE TABLE IF NOT EXISTS tokvault.tokens (
  tenant_id  uuid NOT NULL,
  class      text NOT NULL,
  token_mac  text NOT NULL, -- HMAC of the token's digits under a key derived from the FF1 key
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, class, token_mac)
);
CREATE INDEX IF NOT EXISTS tokens_expiry ON tokvault.tokens (expires_at);
