-- Identity (spec §10.1, ADR-0002): users and groups provisioned by the bank IdP over SCIM, role bindings managed
-- here. Idempotent: applied by identity.Open.
CREATE SCHEMA IF NOT EXISTS identity;

-- doc is the SCIM resource as the IdP sent it (minus id/meta); the columns are what lookups need.
CREATE TABLE IF NOT EXISTS identity.users (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_name   text        NOT NULL,
  active      boolean     NOT NULL DEFAULT true,
  doc         jsonb       NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
-- Token preferred_username matches SCIM userName case-insensitively.
CREATE UNIQUE INDEX IF NOT EXISTS users_user_name ON identity.users (lower(user_name));

CREATE TABLE IF NOT EXISTS identity.groups (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  display_name  text        NOT NULL UNIQUE,
  doc           jsonb       NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS identity.group_members (
  group_id uuid NOT NULL REFERENCES identity.groups(id) ON DELETE CASCADE,
  user_id  uuid NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);

-- Exactly one of user_id / group_id. Deleting the user or group removes its bindings (and that is audited).
CREATE TABLE IF NOT EXISTS identity.role_bindings (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid REFERENCES identity.users(id) ON DELETE CASCADE,
  group_id    uuid REFERENCES identity.groups(id) ON DELETE CASCADE,
  role        text        NOT NULL,
  attrs       jsonb       NOT NULL DEFAULT '{}',
  expires_at  timestamptz,
  created_by  text        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  CHECK ((user_id IS NULL) <> (group_id IS NULL))
);
