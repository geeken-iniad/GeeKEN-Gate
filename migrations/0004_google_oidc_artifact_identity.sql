-- Migration number: 0004 	 2026-06-15T16:50:00.000Z

ALTER TABLE auth_codes ADD COLUMN provider_user_id TEXT;
ALTER TABLE access_tokens ADD COLUMN provider TEXT CHECK (provider IS NULL OR provider IN ('github', 'google'));
ALTER TABLE access_tokens ADD COLUMN provider_user_id TEXT;
