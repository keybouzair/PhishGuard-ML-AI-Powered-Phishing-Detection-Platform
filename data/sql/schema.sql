-- PostgreSQL production schema

CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(64) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  email VARCHAR(255),
  role VARCHAR(16) NOT NULL DEFAULT 'user',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login TIMESTAMPTZ,
  is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS url_checks (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  url TEXT NOT NULL,
  prediction_label VARCHAR(16),
  prediction_score NUMERIC(6,2),
  is_phishing SMALLINT CHECK (is_phishing IN (0,1)),
  checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_url_checks_user_time ON url_checks (username, checked_at DESC);

CREATE TABLE IF NOT EXISTS blocklist (
  id BIGSERIAL PRIMARY KEY,
  url TEXT UNIQUE NOT NULL,
  added_by VARCHAR(64),
  reason TEXT,
  added_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS activity_log (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  action VARCHAR(64) NOT NULL,
  details TEXT,
  ip_address VARCHAR(64),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Optional feedback table for active learning
CREATE TABLE IF NOT EXISTS feedback (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  url TEXT NOT NULL,
  predicted_label SMALLINT CHECK (predicted_label IN (0,1)),
  user_label SMALLINT CHECK (user_label IN (0,1)),
  comment VARCHAR(300),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
