-- Integrity hardening for session accounting.
--
-- `report_sessions` resolves an incoming report against the one *open* row of
-- a (key, server) pair. Without this index, two reports arriving at the same
-- moment could each see "no open row" and insert two. The unique index turns
-- that race into a constraint failure instead of a phantom extra session, and
-- the report path itself now runs inside a transaction.
CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_open_uniq
  ON sessions(key_id, server_id) WHERE ended_at IS NULL;
