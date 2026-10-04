-- Object-storage change feed (ticket 32): bucket event notifications, in arrival order. Idempotent.
CREATE SCHEMA IF NOT EXISTS data;

CREATE TABLE IF NOT EXISTS data.object_events (
  id       bigserial   PRIMARY KEY,
  source   text        NOT NULL,
  bucket   text        NOT NULL,
  key      text        NOT NULL,
  etag     text        NOT NULL DEFAULT '',
  size     bigint      NOT NULL DEFAULT 0,
  deleted  boolean     NOT NULL,
  at       timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS object_events_feed ON data.object_events (source, bucket, id);
