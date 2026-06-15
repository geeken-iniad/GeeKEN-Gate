import { applyD1Migrations } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { describe, expect, it } from 'vitest'

import { normalizeEmail } from '../src/lib/identity'

const NOW = 1_700_000_000
const HASH_A = 'a'.repeat(64)
const HASH_B = 'b'.repeat(64)

async function countRows(table: string) {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS count FROM ${table}`,
  ).first<{ count: number }>()

  return row?.count
}

describe('initial migration', () => {
  it('creates all required application tables', async () => {
    const result = await env.DB.prepare(
      `SELECT name FROM sqlite_master WHERE type = 'table'`,
    ).all<{ name: string }>()
    const tableNames = result.results.map(({ name }) => name)

    expect(tableNames).toEqual(
      expect.arrayContaining([
        'users',
        'members',
        'member_emails',
        'external_identities',
        'clients',
        'allowed_redirect_uris',
        'sessions',
        'oauth_states',
        'auth_codes',
        'auth_events',
      ]),
    )
    expect(tableNames).not.toContain('frozen_users')
  })

  it('creates provider-neutral identity indexes', async () => {
    const result = await env.DB.prepare(
      `SELECT name FROM sqlite_master WHERE type = 'index'`,
    ).all<{ name: string }>()
    const indexNames = result.results.map(({ name }) => name)

    expect(indexNames).toEqual(
      expect.arrayContaining([
        'idx_users_member_id_unique',
        'idx_member_emails_member_id',
        'idx_external_identities_user_id',
        'idx_sessions_user_id',
        'idx_auth_codes_user_id',
        'idx_auth_events_user_id_occurred_at',
      ]),
    )
  })

  it('records migrations only once when reapplied', async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS)

    const row = await env.DB.prepare(
      `SELECT name, COUNT(*) AS count
       FROM d1_migrations
       WHERE name IN (?, ?, ?, ?)
       GROUP BY name`,
    )
      .bind('0001_initial.sql', '0002_identity_membership_model.sql', '0003_oidc_provider.sql', '0004_google_oidc_artifact_identity.sql')
      .all<{ name: string; count: number }>()

    expect(row.results).toEqual(
      expect.arrayContaining([
        { name: '0001_initial.sql', count: 1 },
        { name: '0002_identity_membership_model.sql', count: 1 },
        { name: '0003_oidc_provider.sql', count: 1 },
        { name: '0004_google_oidc_artifact_identity.sql', count: 1 },
      ]),
    )
  })
})

describe('identity and membership records', () => {
  it('stores a complete provider-neutral authentication data graph', async () => {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO members (member_id, display_name, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).bind('member-a', 'Octo Cat', 'active', NOW, NOW),
      env.DB.prepare(
        `INSERT INTO member_emails
           (normalized_email, member_id, login_allowed, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).bind('octo@example.com', 'member-a', 1, NOW, NOW),
      env.DB.prepare(
        `INSERT INTO users (user_id, member_id, created_at, updated_at)
         VALUES (?, ?, ?, ?)`,
      ).bind('user-a', 'member-a', NOW, NOW),
      env.DB.prepare(
        `INSERT INTO external_identities
           (provider, provider_user_id, user_id, provider_login,
            email, email_verified, hosted_domain, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        'github',
        '100',
        'user-a',
        'octocat',
        'octo@example.com',
        null,
        null,
        NOW,
        NOW,
      ),
      env.DB.prepare(
        `INSERT INTO clients (client_id, client_secret_hash, created_at)
         VALUES (?, ?, ?)`,
      ).bind('client-a', HASH_A, NOW),
      env.DB.prepare(
        `INSERT INTO allowed_redirect_uris (client_id, redirect_uri, created_at)
         VALUES (?, ?, ?)`,
      ).bind('client-a', 'https://client.example/callback', NOW),
    ])

    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO sessions (session_hash, user_id, created_at, expires_at)
         VALUES (?, ?, ?, ?)`,
      ).bind(HASH_A, 'user-a', NOW, NOW + 60),
      env.DB.prepare(
        `INSERT INTO auth_codes
           (code_hash, user_id, client_id, redirect_uri, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(HASH_B, 'user-a', 'client-a', 'https://client.example/callback', NOW, NOW + 60),
    ])

    expect(await countRows('member_emails')).toBe(1)
    expect(await countRows('external_identities')).toBe(1)
    expect(await countRows('sessions')).toBe(1)
    expect(await countRows('auth_codes')).toBe(1)
  })

  it('enforces membership, provider, and login eligibility constraints', async () => {
    await env.DB.prepare(
      `INSERT INTO members (member_id, display_name, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
      .bind('member-a', 'Octo Cat', 'active', NOW, NOW)
      .run()

    await expect(
      env.DB.prepare(
        `INSERT INTO members (member_id, display_name, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
        .bind('member-b', 'Suspicious', 'paused', NOW, NOW)
        .run(),
    ).rejects.toThrow()
    await expect(
      env.DB.prepare(
        `INSERT INTO member_emails
           (normalized_email, member_id, login_allowed, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
        .bind('octo@example.com', 'member-a', 2, NOW, NOW)
        .run(),
    ).rejects.toThrow()
    await expect(
      env.DB.prepare(
        `INSERT INTO external_identities
           (provider, provider_user_id, user_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
        .bind('twitter', '100', 'missing-user', NOW, NOW)
        .run(),
    ).rejects.toThrow()
  })

  it('allows only one user for a non-null member_id', async () => {
    await env.DB.prepare(
      `INSERT INTO members (member_id, display_name, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
      .bind('member-a', 'Octo Cat', 'active', NOW, NOW)
      .run()
    await env.DB.prepare(
      `INSERT INTO users (user_id, member_id, created_at, updated_at)
       VALUES (?, ?, ?, ?)`,
    )
      .bind('user-a', 'member-a', NOW, NOW)
      .run()

    await expect(
      env.DB.prepare(
        `INSERT INTO users (user_id, member_id, created_at, updated_at)
         VALUES (?, ?, ?, ?)`,
      )
        .bind('user-b', 'member-a', NOW, NOW)
        .run(),
    ).rejects.toThrow()

    await env.DB.prepare(
      `INSERT INTO users (user_id, created_at, updated_at)
       VALUES (?, ?, ?)`,
    )
      .bind('user-c', NOW, NOW)
      .run()
    await env.DB.prepare(
      `INSERT INTO users (user_id, created_at, updated_at)
       VALUES (?, ?, ?)`,
    )
      .bind('user-d', NOW, NOW)
      .run()
  })

  it('uses conservative email normalization', () => {
    expect(normalizeEmail('  Octo.Cat+dev@Example.COM  ')).toBe(
      'octo.cat+dev@example.com',
    )
  })
})
