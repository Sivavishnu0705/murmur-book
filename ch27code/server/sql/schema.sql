-- schema.sql — what murmur-api and murmur-relay store. Nothing here decrypts a message.
-- Every table is keyed by device; revocation deletes by device_id (Listing 27.3 cascade).
CREATE TABLE identity_keys (
  device_id    text PRIMARY KEY,
  account_id   text NOT NULL,
  identity_key bytea NOT NULL CHECK (octet_length(identity_key) = 32),
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE signed_prekeys (            -- kind 'ec' = SPK (rotated weekly), 'pq' = last-resort PQ prekey
  device_id  text NOT NULL,
  kind       text NOT NULL CHECK (kind IN ('ec', 'pq')),
  key_id     integer NOT NULL,
  public_key bytea NOT NULL,
  signature  bytea NOT NULL CHECK (octet_length(signature) = 64),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, kind, key_id)
);
CREATE TABLE one_time_prekeys (          -- kind 'ec' = OPK (unsigned), 'pq' = one-time PQ prekey (signed)
  device_id  text NOT NULL,
  kind       text NOT NULL CHECK (kind IN ('ec', 'pq')),
  key_id     integer NOT NULL,
  public_key bytea NOT NULL,
  signature  bytea,
  PRIMARY KEY (device_id, kind, key_id)
);
CREATE TABLE envelopes (                 -- relay queues: opaque bytes, no sender column
  guid        bytea PRIMARY KEY,
  device_id   text NOT NULL,
  seq         bigserial,
  body        bytea NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),   -- truncated to the minute by the relay
  expires_at  timestamptz NOT NULL
);
CREATE INDEX envelopes_by_device ON envelopes (device_id, seq);
CREATE TABLE queue_quota (
  device_id text PRIMARY KEY,
  n         integer NOT NULL DEFAULT 0,
  bytes     bigint  NOT NULL DEFAULT 0
);
CREATE TABLE mls_groups (
  group_id bytea PRIMARY KEY,
  epoch    bigint NOT NULL DEFAULT 0
);
CREATE TABLE mls_handshake_log (         -- the single ordered handshake log per group (Ch 23 §23.8)
  group_id bytea NOT NULL,
  epoch    bigint NOT NULL,
  message  bytea NOT NULL,
  PRIMARY KEY (group_id, epoch)          -- a second commit for one epoch cannot even be stored
);
