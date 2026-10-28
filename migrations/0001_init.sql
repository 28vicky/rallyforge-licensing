-- RallyForge accounts + licensing (beta). All times are server time in ms since epoch.

CREATE TABLE accounts (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,          -- stored lower-case
  password_hash TEXT NOT NULL,
  plan          TEXT NOT NULL DEFAULT 'trial', -- 'trial' | 'paid'
  instance_limit INTEGER NOT NULL DEFAULT 0,
  device_limit  INTEGER NOT NULL DEFAULT 5,
  expires_at    INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  notes         TEXT NOT NULL DEFAULT '',
  flagged       TEXT NOT NULL DEFAULT ''       -- non-empty = look at it in admin (never auto-ban)
);

-- One row per signed-in PC.
CREATE TABLE devices (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,
  hw_id       TEXT NOT NULL DEFAULT '',  -- hardware fingerprint sent by the app (hashed by the app)
  name        TEXT NOT NULL DEFAULT '',
  app_version TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL
);
CREATE INDEX devices_account ON devices(account_id);

-- One row per running instance ("seat"). Ends by itself after LEASE_TTL without a heartbeat.
CREATE TABLE leases (
  device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  emulator    TEXT NOT NULL,             -- ADB address, e.g. 127.0.0.1:16416
  account_id  TEXT NOT NULL,
  name        TEXT NOT NULL DEFAULT '',  -- instance name shown on the account card
  started_at  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL,
  PRIMARY KEY (device_id, emulator)
);
CREATE INDEX leases_account ON leases(account_id, last_seen);

CREATE TABLE reset_codes (
  code_hash  TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0
);

-- Owner's manual payment record (written by "Add days" in admin).
CREATE TABLE payments (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  date       INTEGER NOT NULL,
  amount     REAL NOT NULL DEFAULT 0,
  currency   TEXT NOT NULL DEFAULT '',
  method     TEXT NOT NULL DEFAULT '',
  days_added INTEGER NOT NULL DEFAULT 0,
  instances  INTEGER NOT NULL DEFAULT 0,
  note       TEXT NOT NULL DEFAULT ''
);

-- One trial per PC (hw_id), against trial farming with fresh emails.
CREATE TABLE trial_pcs (
  hw_id      TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- Audit log: lease grant/deny/expire, plan changes, sign-ins, resets.
CREATE TABLE events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  account_id TEXT NOT NULL DEFAULT '',
  kind       TEXT NOT NULL,
  detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX events_account ON events(account_id, ts);

CREATE TABLE rate_limits (
  key          TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL
);
