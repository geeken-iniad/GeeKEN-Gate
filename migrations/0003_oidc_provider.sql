-- Migration number: 0003 	 2026-06-15T12:00:00.000Z

DELETE FROM oauth_states;
DELETE FROM auth_codes;

ALTER TABLE oauth_states ADD COLUMN client_state TEXT;
ALTER TABLE oauth_states ADD COLUMN scope TEXT;
ALTER TABLE oauth_states ADD COLUMN nonce TEXT;
ALTER TABLE oauth_states ADD COLUMN provider TEXT CHECK (provider IS NULL OR provider IN ('github', 'google'));
ALTER TABLE oauth_states ADD COLUMN code_challenge TEXT;
ALTER TABLE oauth_states ADD COLUMN code_challenge_method TEXT CHECK (code_challenge_method IS NULL OR code_challenge_method IN ('S256', 'plain'));

ALTER TABLE auth_codes ADD COLUMN scope TEXT;
ALTER TABLE auth_codes ADD COLUMN nonce TEXT;
ALTER TABLE auth_codes ADD COLUMN provider TEXT CHECK (provider IS NULL OR provider IN ('github', 'google'));
ALTER TABLE auth_codes ADD COLUMN auth_time INTEGER;
ALTER TABLE auth_codes ADD COLUMN code_challenge TEXT;
ALTER TABLE auth_codes ADD COLUMN code_challenge_method TEXT CHECK (code_challenge_method IS NULL OR code_challenge_method IN ('S256', 'plain'));

CREATE TABLE access_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (user_id)
    REFERENCES users(user_id)
    ON DELETE CASCADE,
  FOREIGN KEY (client_id)
    REFERENCES clients(client_id)
    ON DELETE CASCADE,
  CHECK (
    length(token_hash) = 64
    AND token_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (expires_at > created_at)
) STRICT;

CREATE INDEX idx_access_tokens_user_id
  ON access_tokens(user_id);

CREATE INDEX idx_access_tokens_expires_at
  ON access_tokens(expires_at);
