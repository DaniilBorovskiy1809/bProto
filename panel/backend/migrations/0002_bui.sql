-- bUI: inbounds, subscriptions and remote subscription sources.
--
-- Model (mirrors the 3x-ui vocabulary the panel UI uses):
--   * inbound  — one bProto endpoint clients connect to: `server` (host:port),
--                the donor SNI whose TLS identity the handshake borrows, and the
--                ClientHello fingerprint. "Enabling" an inbound only marks it
--                for the panel; the server keeps its own listener config.
--   * client   — a `users` row with `inbound_id` set. It owns `keys` (one per
--                device the config was imported on). The routing tag is
--                HMAC(K_tag, user_id), so a user id identifies the client on
--                every server of one deployment.
--   * sub_id   — opaque subscription id; `/sub/<sub_id>` hands the client all
--                its active configs plus the configs of attached remote
--                subscription sources.

-- ---------------------------------------------------------------------------
-- Inbounds
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS inbounds (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    remark      TEXT NOT NULL,                        -- "DE-Frankfurt"
    server      TEXT NOT NULL,                        -- host:port clients dial
    donor_sni   TEXT NOT NULL,                        -- borrowed TLS identity
    fingerprint TEXT NOT NULL DEFAULT 'chrome112',
    protocol    TEXT NOT NULL DEFAULT 'bproto',
    transport   TEXT NOT NULL DEFAULT 'udp',
    listen_port INTEGER,                              -- informational only
    status      TEXT NOT NULL DEFAULT 'active',       -- active | disabled
    note        TEXT,
    created_at  INTEGER NOT NULL
);

-- A client belongs to exactly one inbound; admins have NULL here.
ALTER TABLE users ADD COLUMN inbound_id INTEGER REFERENCES inbounds(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN sub_id TEXT;
ALTER TABLE users ADD COLUMN note TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_sub ON users(sub_id);

-- ---------------------------------------------------------------------------
-- Subscription sources hosted by another bProto panel
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS remote_subs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    url           TEXT NOT NULL UNIQUE,
    enabled       INTEGER NOT NULL DEFAULT 1,
    last_fetch_at INTEGER,
    last_status   TEXT,                               -- ok | error
    last_error    TEXT,
    entry_count   INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);

-- One row per config found in a remote subscription. `uri` carries the remote
-- deployment's credential (psk inside the base64 payload), because the panel
-- has to be able to re-serve it; treat this table as secret.
CREATE TABLE IF NOT EXISTS remote_sub_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sub_id      INTEGER NOT NULL REFERENCES remote_subs(id) ON DELETE CASCADE,
    uri         TEXT NOT NULL,
    server      TEXT,
    sni         TEXT,
    uid         INTEGER,
    label       TEXT,
    fingerprint TEXT,
    fetched_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_remote_entries_sub ON remote_sub_entries(sub_id);

-- Remote sources attached to a client: its subscription then aggregates them.
CREATE TABLE IF NOT EXISTS user_remote_subs (
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    remote_sub_id INTEGER NOT NULL REFERENCES remote_subs(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, remote_sub_id)
);

-- ---------------------------------------------------------------------------
-- Panel settings (subscription base URL / title; anything else that is a knob
-- rather than a row). Values stay TEXT; readers parse.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Session accounting: the servers report deltas; the panel needs to tell a live
-- session from an abandoned row, so it stamps every update.
ALTER TABLE sessions ADD COLUMN updated_at INTEGER;
