-- Migration number: 0001 	 2026-06-17T00:00:00.000Z

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  updated_at INTEGER NOT NULL CHECK (updated_at > 0),
  CHECK (length(id) > 0),
  CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE github_identities (
  github_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  github_login TEXT,
  frozen_at INTEGER,
  freeze_reason TEXT,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  updated_at INTEGER NOT NULL CHECK (updated_at > 0),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CHECK (length(github_id) > 0),
  CHECK (length(user_id) > 0),
  CHECK (updated_at >= created_at)
) STRICT;

CREATE INDEX idx_github_identities_user_id
  ON github_identities(user_id);

CREATE INDEX idx_github_identities_frozen_at
  ON github_identities(frozen_at);

CREATE TABLE google_identities (
  google_issuer TEXT NOT NULL,
  google_sub TEXT NOT NULL,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  last_seen_at INTEGER NOT NULL CHECK (last_seen_at > 0),
  PRIMARY KEY (google_issuer, google_sub),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CHECK (length(google_issuer) > 0),
  CHECK (length(google_sub) > 0),
  CHECK (length(user_id) > 0)
) STRICT;

CREATE INDEX idx_google_identities_user_id
  ON google_identities(user_id);

CREATE TABLE google_login_allowlist (
  email_hash TEXT NOT NULL,
  pepper_version INTEGER NOT NULL,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  disabled_at INTEGER,
  PRIMARY KEY (email_hash, pepper_version),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CHECK (
    length(email_hash) = 64
    AND email_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (length(user_id) > 0),
  CHECK (disabled_at IS NULL OR disabled_at >= created_at)
) STRICT;

CREATE INDEX idx_google_allowlist_user_id
  ON google_login_allowlist(user_id);

CREATE INDEX idx_google_allowlist_disabled_at
  ON google_login_allowlist(disabled_at);

CREATE TABLE clients (
  client_id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  disabled_at INTEGER,
  CHECK (length(client_id) > 0),
  CHECK (disabled_at IS NULL OR disabled_at >= created_at)
) STRICT;

CREATE INDEX idx_clients_disabled_at
  ON clients(disabled_at);

CREATE TABLE allowed_redirect_uris (
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  PRIMARY KEY (client_id, redirect_uri),
  FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
  CHECK (length(redirect_uri) > 0)
) STRICT;

CREATE TABLE oauth_states (
  upstream_state_hash TEXT PRIMARY KEY,
  client_state TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  nonce TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  provider TEXT,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (client_id, redirect_uri)
    REFERENCES allowed_redirect_uris(client_id, redirect_uri)
    ON DELETE CASCADE,
  CHECK (
    length(upstream_state_hash) = 64
    AND upstream_state_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (length(client_state) > 0),
  CHECK (length(client_id) > 0),
  CHECK (length(redirect_uri) > 0),
  CHECK (length(nonce) > 0),
  CHECK (length(code_challenge) > 0),
  CHECK (code_challenge_method = 'S256'),
  CHECK (provider IS NULL OR provider IN ('github', 'google')),
  CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX idx_oauth_states_expires_at
  ON oauth_states(expires_at);

CREATE TABLE auth_codes (
  code_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  nonce TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (client_id, redirect_uri)
    REFERENCES allowed_redirect_uris(client_id, redirect_uri)
    ON DELETE CASCADE,
  CHECK (
    length(code_hash) = 64
    AND code_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (length(user_id) > 0),
  CHECK (length(client_id) > 0),
  CHECK (length(redirect_uri) > 0),
  CHECK (length(nonce) > 0),
  CHECK (length(code_challenge) > 0),
  CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX idx_auth_codes_user_id
  ON auth_codes(user_id);

CREATE INDEX idx_auth_codes_expires_at
  ON auth_codes(expires_at);

CREATE TABLE access_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
  CHECK (
    length(token_hash) = 64
    AND token_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (length(user_id) > 0),
  CHECK (length(client_id) > 0),
  CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX idx_access_tokens_user_id
  ON access_tokens(user_id);

CREATE INDEX idx_access_tokens_client_id
  ON access_tokens(client_id);

CREATE INDEX idx_access_tokens_expires_at
  ON access_tokens(expires_at);

CREATE TABLE refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE,
  CHECK (
    length(token_hash) = 64
    AND token_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (length(user_id) > 0),
  CHECK (length(client_id) > 0),
  CHECK (expires_at > created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
) STRICT;

CREATE INDEX idx_refresh_tokens_user_id
  ON refresh_tokens(user_id);

CREATE INDEX idx_refresh_tokens_client_id
  ON refresh_tokens(client_id);

CREATE INDEX idx_refresh_tokens_expires_at
  ON refresh_tokens(expires_at);

CREATE INDEX idx_refresh_tokens_revoked_at
  ON refresh_tokens(revoked_at);

CREATE TABLE auth_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  provider TEXT,
  user_id TEXT,
  github_id TEXT,
  github_login TEXT,
  google_issuer TEXT,
  google_sub TEXT,
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

CREATE INDEX idx_auth_events_user_id_occurred_at
  ON auth_events(user_id, occurred_at);

CREATE INDEX idx_auth_events_github_id_occurred_at
  ON auth_events(github_id, occurred_at);

CREATE INDEX idx_auth_events_google_sub_occurred_at
  ON auth_events(google_sub, occurred_at);

CREATE INDEX idx_auth_events_client_id_occurred_at
  ON auth_events(client_id, occurred_at);
