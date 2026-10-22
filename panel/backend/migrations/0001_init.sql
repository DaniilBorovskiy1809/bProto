-- bProto control panel schema. The panel is the single source of truth; the
-- server keeps only an in-memory snapshot synced over the loopback admin API.

-- journal_mode = WAL and foreign_keys = ON are set on every pooled connection
-- in src/main.rs; setting them here would apply to one connection only.

CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    is_admin            INTEGER NOT NULL DEFAULT 0,
    traffic_limit_bytes INTEGER,            -- NULL = unlimited
    traffic_used_bytes  INTEGER NOT NULL DEFAULT 0,
    expires_at          INTEGER,            -- unix seconds, NULL = never
    status              TEXT NOT NULL DEFAULT 'active',  -- active|disabled|revoked
    created_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label        TEXT NOT NULL DEFAULT 'device',
    psk          BLOB NOT NULL,             -- 32 bytes
    tag          BLOB NOT NULL,             -- HMAC(K_tag, user_id)[0..8]
    status       TEXT NOT NULL DEFAULT 'active',  -- active|revoked
    created_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    last_seen_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_keys_user ON keys(user_id);

CREATE TABLE IF NOT EXISTS servers (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    host       TEXT NOT NULL,
    donor_url  TEXT,
    status     TEXT NOT NULL DEFAULT 'online'
);

CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id     INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    server_id  TEXT,
    started_at INTEGER NOT NULL,
    ended_at   INTEGER,
    bytes_rx   INTEGER NOT NULL DEFAULT 0,
    bytes_tx   INTEGER NOT NULL DEFAULT 0,
    peer_ip    TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_key ON sessions(key_id);

CREATE TABLE IF NOT EXISTS admin_sessions (
    token      TEXT PRIMARY KEY,            -- 32-byte hex, opaque
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    action   TEXT NOT NULL,
    target   TEXT,
    at       INTEGER NOT NULL,
    ip       TEXT
);
