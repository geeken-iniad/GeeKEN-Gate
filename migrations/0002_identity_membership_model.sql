-- Migration number: 0002 	 2026-06-15T11:20:00.000Z

PRAGMA foreign_keys = OFF;

ALTER TABLE users RENAME TO users_legacy;
ALTER TABLE sessions RENAME TO sessions_legacy;
ALTER TABLE auth_codes RENAME TO auth_codes_legacy;
ALTER TABLE auth_events RENAME TO auth_events_legacy;
ALTER TABLE frozen_users RENAME TO frozen_users_legacy;

CREATE TABLE identity_migration_map (
  github_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL UNIQUE
) STRICT;

INSERT INTO identity_migration_map (github_id, user_id)
SELECT github_id, lower(hex(randomblob(16)))
FROM users_legacy;

INSERT INTO identity_migration_map (github_id, user_id)
SELECT frozen_users_legacy.github_id, lower(hex(randomblob(16)))
FROM frozen_users_legacy
LEFT JOIN identity_migration_map
  ON identity_migration_map.github_id = frozen_users_legacy.github_id
WHERE identity_migration_map.github_id IS NULL;

CREATE TABLE members (
  member_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'left')),
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  updated_at INTEGER NOT NULL CHECK (updated_at > 0),
  CHECK (length(member_id) > 0),
  CHECK (length(display_name) > 0),
  CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE member_emails (
  normalized_email TEXT PRIMARY KEY,
  member_id TEXT NOT NULL,
  login_allowed INTEGER NOT NULL CHECK (login_allowed IN (0, 1)),
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  updated_at INTEGER NOT NULL CHECK (updated_at > 0),
  FOREIGN KEY (member_id)
    REFERENCES members(member_id)
    ON DELETE CASCADE,
  CHECK (length(normalized_email) > 0),
  CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE users (
  user_id TEXT PRIMARY KEY,
  member_id TEXT,
  disabled_at INTEGER,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  updated_at INTEGER NOT NULL CHECK (updated_at > 0),
  FOREIGN KEY (member_id)
    REFERENCES members(member_id)
    ON DELETE SET NULL,
  CHECK (length(user_id) > 0),
  CHECK (disabled_at IS NULL OR disabled_at >= created_at),
  CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE external_identities (
  provider TEXT NOT NULL CHECK (provider IN ('github', 'google')),
  provider_user_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  provider_login TEXT,
  email TEXT,
  email_verified INTEGER CHECK (email_verified IS NULL OR email_verified IN (0, 1)),
  hosted_domain TEXT,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  updated_at INTEGER NOT NULL CHECK (updated_at > 0),
  PRIMARY KEY (provider, provider_user_id),
  FOREIGN KEY (user_id)
    REFERENCES users(user_id)
    ON DELETE CASCADE,
  CHECK (length(provider_user_id) > 0),
  CHECK (updated_at >= created_at)
) STRICT;

CREATE TABLE sessions (
  session_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (user_id)
    REFERENCES users(user_id)
    ON DELETE CASCADE,
  CHECK (
    length(session_hash) = 64
    AND session_hash NOT GLOB '*[^0-9a-f]*'
  ),
  CHECK (expires_at > created_at)
) STRICT;

CREATE TABLE auth_codes (
  code_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  created_at INTEGER NOT NULL CHECK (created_at > 0),
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (user_id)
    REFERENCES users(user_id)
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

CREATE TABLE auth_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  user_id TEXT,
  provider TEXT CHECK (provider IS NULL OR provider IN ('github', 'google')),
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

INSERT INTO users (user_id, disabled_at, created_at, updated_at)
SELECT
  identity_migration_map.user_id,
  frozen_users_legacy.frozen_at,
  users_legacy.created_at,
  CASE
    WHEN frozen_users_legacy.frozen_at IS NOT NULL
      AND frozen_users_legacy.frozen_at > users_legacy.updated_at
    THEN frozen_users_legacy.frozen_at
    ELSE users_legacy.updated_at
  END
FROM users_legacy
INNER JOIN identity_migration_map
  ON identity_migration_map.github_id = users_legacy.github_id
LEFT JOIN frozen_users_legacy
  ON frozen_users_legacy.github_id = users_legacy.github_id;

INSERT INTO external_identities
  (provider, provider_user_id, user_id, provider_login, created_at, updated_at)
SELECT
  'github',
  users_legacy.github_id,
  identity_migration_map.user_id,
  users_legacy.github_login,
  users_legacy.created_at,
  users_legacy.updated_at
FROM users_legacy
INNER JOIN identity_migration_map
  ON identity_migration_map.github_id = users_legacy.github_id;

INSERT INTO users (user_id, disabled_at, created_at, updated_at)
SELECT
  identity_migration_map.user_id,
  frozen_users_legacy.frozen_at,
  frozen_users_legacy.frozen_at,
  frozen_users_legacy.frozen_at
FROM frozen_users_legacy
INNER JOIN identity_migration_map
  ON identity_migration_map.github_id = frozen_users_legacy.github_id
LEFT JOIN users_legacy
  ON users_legacy.github_id = frozen_users_legacy.github_id
WHERE users_legacy.github_id IS NULL;

INSERT INTO external_identities
  (provider, provider_user_id, user_id, provider_login, created_at, updated_at)
SELECT
  'github',
  frozen_users_legacy.github_id,
  identity_migration_map.user_id,
  NULL,
  frozen_users_legacy.frozen_at,
  frozen_users_legacy.frozen_at
FROM frozen_users_legacy
INNER JOIN identity_migration_map
  ON identity_migration_map.github_id = frozen_users_legacy.github_id
LEFT JOIN users_legacy
  ON users_legacy.github_id = frozen_users_legacy.github_id
WHERE users_legacy.github_id IS NULL;

INSERT INTO sessions (session_hash, user_id, created_at, expires_at)
SELECT sessions_legacy.session_hash, external_identities.user_id,
       sessions_legacy.created_at, sessions_legacy.expires_at
FROM sessions_legacy
INNER JOIN external_identities
  ON external_identities.provider = 'github'
 AND external_identities.provider_user_id = sessions_legacy.github_id;

INSERT INTO auth_codes
  (code_hash, user_id, client_id, redirect_uri, created_at, expires_at)
SELECT auth_codes_legacy.code_hash, external_identities.user_id,
       auth_codes_legacy.client_id, auth_codes_legacy.redirect_uri,
       auth_codes_legacy.created_at, auth_codes_legacy.expires_at
FROM auth_codes_legacy
INNER JOIN external_identities
  ON external_identities.provider = 'github'
 AND external_identities.provider_user_id = auth_codes_legacy.github_id;

INSERT INTO auth_events
  (id, event_type, user_id, provider, github_id, github_login, client_id,
   redirect_uri, success, reason, ip_address, user_agent, occurred_at)
SELECT auth_events_legacy.id, auth_events_legacy.event_type,
       external_identities.user_id,
       CASE WHEN auth_events_legacy.github_id IS NULL THEN NULL ELSE 'github' END,
       auth_events_legacy.github_id, auth_events_legacy.github_login,
       auth_events_legacy.client_id, auth_events_legacy.redirect_uri,
       auth_events_legacy.success, auth_events_legacy.reason,
       auth_events_legacy.ip_address, auth_events_legacy.user_agent,
       auth_events_legacy.occurred_at
FROM auth_events_legacy
LEFT JOIN external_identities
  ON external_identities.provider = 'github'
 AND external_identities.provider_user_id = auth_events_legacy.github_id;

DROP TABLE sessions_legacy;
DROP TABLE auth_codes_legacy;
DROP TABLE auth_events_legacy;
DROP TABLE frozen_users_legacy;
DROP TABLE users_legacy;
DROP TABLE identity_migration_map;

CREATE UNIQUE INDEX idx_users_member_id_unique
  ON users(member_id)
  WHERE member_id IS NOT NULL;

CREATE INDEX idx_member_emails_member_id
  ON member_emails(member_id);

CREATE INDEX idx_external_identities_user_id
  ON external_identities(user_id);

CREATE INDEX idx_sessions_user_id
  ON sessions(user_id);

CREATE INDEX idx_sessions_expires_at
  ON sessions(expires_at);

CREATE INDEX idx_auth_codes_user_id
  ON auth_codes(user_id);

CREATE INDEX idx_auth_codes_expires_at
  ON auth_codes(expires_at);

CREATE INDEX idx_auth_events_occurred_at
  ON auth_events(occurred_at);

CREATE INDEX idx_auth_events_event_type_occurred_at
  ON auth_events(event_type, occurred_at);

CREATE INDEX idx_auth_events_user_id_occurred_at
  ON auth_events(user_id, occurred_at);

CREATE INDEX idx_auth_events_github_id_occurred_at
  ON auth_events(github_id, occurred_at);

CREATE INDEX idx_auth_events_client_id_occurred_at
  ON auth_events(client_id, occurred_at);

PRAGMA foreign_keys = ON;
