-- Migration number: 0001 	 2026-06-12T23:27:52.653Z

CREATE TABLE users (
  github_id TEXT PRIMARY KEY,
  github_login TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  updated_at INTEGER NOT NULL CHECK (updated_at > 0),
  CHECK (length(github_id) > 0),
  CHECK (length(github_login) > 0),
  CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE frozen_users (
  github_id TEXT PRIMARY KEY,
  frozen_at INTEGER NOT NULL CHECK (frozen_at > 0),
  reason TEXT,
  CHECK (length(github_id) > 0)
) STRICT;

CREATE TABLE clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  disabled_at INTEGER,
  CHECK (length(client_id) > 0),
  CHECK (
    length(client_secret_hash) = 64
    AND client_secret_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (disabled_at IS NULL OR disabled_at >= created_at)
) STRICT;

CREATE TABLE allowed_redirect_uris (
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  PRIMARY KEY (client_id, redirect_uri),
  FOREIGN KEY (client_id)
    REFERENCES clients(client_id)
    ON DELETE CASCADE,
  CHECK (length(redirect_uri) > 0)
) STRICT;

CREATE TABLE oauth_states (
  state_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (client_id, redirect_uri)
    REFERENCES allowed_redirect_uris(client_id, redirect_uri)
    ON DELETE CASCADE,
  CHECK (
    length(state_hash) = 64
    AND state_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX idx_oauth_states_expires_at
  ON oauth_states(expires_at);

CREATE TABLE auth_codes (
  code_hash TEXT PRIMARY KEY,
  github_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (github_id)
    REFERENCES users(github_id)
    ON DELETE CASCADE,
  FOREIGN KEY (client_id, redirect_uri)
    REFERENCES allowed_redirect_uris(client_id, redirect_uri)
    ON DELETE CASCADE,
  CHECK (
    length(code_hash) = 64
    AND code_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX idx_auth_codes_github_id
  ON auth_codes(github_id);

CREATE INDEX idx_auth_codes_expires_at
  ON auth_codes(expires_at);

CREATE TABLE auth_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  github_id TEXT,
  github_login TEXT,
  client_id TEXT,
  redirect_uri TEXT,
  success INTEGER NOT NULL,
  reason TEXT,
  ip_address TEXT,
  user_agent TEXT,
  occurred_at INTEGER NOT NULL,
  CHECK (success IN (0, 1)),
  CHECK (occurred_at > 0),
  CHECK (length(event_type) > 0)
) STRICT;

CREATE INDEX idx_auth_events_occurred_at
  ON auth_events(occurred_at);

CREATE INDEX idx_auth_events_event_type_occurred_at
  ON auth_events(event_type, occurred_at);

CREATE INDEX idx_auth_events_github_id_occurred_at
  ON auth_events(github_id, occurred_at);

CREATE INDEX idx_auth_events_client_id_occurred_at
  ON auth_events(client_id, occurred_at);
