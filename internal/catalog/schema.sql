-- AI app catalog (spec §4.1, §6 AI_APP / APP_USAGE_DAILY). Idempotent: applied by catalog.Open.
CREATE SCHEMA IF NOT EXISTS catalog;

-- Every imported feed version, kept whole; the highest version is current.
CREATE TABLE IF NOT EXISTS catalog.feeds (
  version      bigint PRIMARY KEY,
  sha256       text        NOT NULL,
  apps         jsonb       NOT NULL,
  source       text        NOT NULL CHECK (source IN ('seed', 'signed')),
  imported_by  text        NOT NULL,
  imported_at  timestamptz NOT NULL DEFAULT now()
);

-- Bank decisions and corrections over the feed (FR-DISC-4/5), and apps the feed does not know (local).
CREATE TABLE IF NOT EXISTS catalog.overrides (
  app_id            text PRIMARY KEY,
  sanction          text CHECK (sanction IN ('sanctioned','tolerated','unsanctioned','blocked','under_review')),
  owner             text,
  reason            text,
  review_at         date,
  hosting_region    text CHECK (hosting_region ~ '^([A-Z]{2}|unknown)$'),
  ojk_approval_ref  text,
  trains_on_data    boolean,
  local             jsonb,  -- full App definition when the app is not in any feed
  updated_by        text        NOT NULL,
  updated_at        timestamptz NOT NULL DEFAULT now()
);

-- APP_USAGE_DAILY from decision events, apps outside the catalog included (shadow AI).
CREATE TABLE IF NOT EXISTS catalog.usage_daily (
  app_id            text NOT NULL,
  day               date NOT NULL,
  events            bigint NOT NULL DEFAULT 0,
  sensitive_events  bigint NOT NULL DEFAULT 0,
  blocked           bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (app_id, day)
);
CREATE TABLE IF NOT EXISTS catalog.usage_users (
  app_id     text NOT NULL,
  day        date NOT NULL,
  principal  text NOT NULL,  -- HMAC pseudonym from the event
  PRIMARY KEY (app_id, day, principal)
);
-- Redelivered events must not count twice; kept a few days.
CREATE TABLE IF NOT EXISTS catalog.usage_seen (
  event_id  uuid PRIMARY KEY,
  day       date NOT NULL
);
