CREATE TABLE IF NOT EXISTS players (
  name_key     TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  pin_hash     TEXT NOT NULL,
  salt         TEXT NOT NULL,
  best_score   INTEGER NOT NULL DEFAULT 0,
  best_level   INTEGER NOT NULL DEFAULT 0,
  best_lines   INTEGER NOT NULL DEFAULT 0,
  games        INTEGER NOT NULL DEFAULT 0,
  fails        INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  lockouts     INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_fails (
  ip           TEXT PRIMARY KEY,
  fails        INTEGER NOT NULL,
  window_start INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scores (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name_key   TEXT NOT NULL,
  score      INTEGER NOT NULL,
  level      INTEGER NOT NULL,
  lines      INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_players_best ON players (best_score DESC);
CREATE INDEX IF NOT EXISTS idx_scores_player ON scores (name_key, created_at DESC);
