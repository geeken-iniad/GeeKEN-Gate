import { applyD1Migrations } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { describe, expect, it } from 'vitest'

const NOW = 1_700_000_000
const HASH_A = 'a'.repeat(64)
const HASH_B = 'b'.repeat(64)
const USER_ID = 'user-uuid'

async function insertUser(userId = USER_ID) {
  await env.DB.prepare(
    `INSERT INTO users (id, created_at, updated_at)
     VALUES (?, ?, ?)`,
  )
    .bind(userId, NOW, NOW)
    .run()
}

async function insertClient(clientId = 'client-a') {
  await env.DB.prepare(
    `INSERT INTO clients (client_id, created_at)
     VALUES (?, ?)`,
  )
    .bind(clientId, NOW)
    .run()
}

async function insertRedirectUri(
  clientId = 'client-a',
  redirectUri = 'https://client.example/callback',
) {
  await env.DB.prepare(
    `INSERT INTO allowed_redirect_uris
       (client_id, redirect_uri, created_at)
     VALUES (?, ?, ?)`,
  )
    .bind(clientId, redirectUri, NOW)
    .run()
}

async function insertClientWithRedirect(
  clientId = 'client-a',
  redirectUri = 'https://client.example/callback',
) {
  await insertClient(clientId)
  await insertRedirectUri(clientId, redirectUri)
}

async function countRows(table: string) {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS count FROM ${table}`,
  ).first<{ count: number }>()

  return row?.count
}

describe('initial migration', () => {
  it('creates all required application tables', async () => {
    const result = await env.DB.prepare(
      `SELECT name
       FROM sqlite_master
       WHERE type = 'table'`,
    ).all<{ name: string }>()
    const tableNames = result.results.map(({ name }) => name)

    expect(tableNames).toEqual(
      expect.arrayContaining([
        'users',
        'github_identities',
        'google_identities',
        'google_login_allowlist',
        'clients',
        'allowed_redirect_uris',
        'oauth_states',
        'auth_codes',
        'access_tokens',
        'refresh_tokens',
        'auth_events',
      ]),
    )
    expect(tableNames).not.toContain('sessions')
    expect(tableNames).not.toContain('frozen_users')
  })

  it('creates all required indexes', async () => {
    const result = await env.DB.prepare(
      `SELECT name
       FROM sqlite_master
       WHERE type = 'index'`,
    ).all<{ name: string }>()
    const indexNames = result.results.map(({ name }) => name)

    expect(indexNames).toEqual(
      expect.arrayContaining([
        'idx_github_identities_user_id',
        'idx_github_identities_frozen_at',
        'idx_google_identities_user_id',
        'idx_google_allowlist_user_id',
        'idx_google_allowlist_disabled_at',
        'idx_clients_disabled_at',
        'idx_oauth_states_expires_at',
        'idx_auth_codes_user_id',
        'idx_auth_codes_expires_at',
        'idx_access_tokens_user_id',
        'idx_access_tokens_client_id',
        'idx_access_tokens_expires_at',
        'idx_refresh_tokens_user_id',
        'idx_refresh_tokens_client_id',
        'idx_refresh_tokens_expires_at',
        'idx_refresh_tokens_revoked_at',
        'idx_auth_events_occurred_at',
        'idx_auth_events_event_type_occurred_at',
        'idx_auth_events_user_id_occurred_at',
        'idx_auth_events_github_id_occurred_at',
        'idx_auth_events_google_sub_occurred_at',
        'idx_auth_events_client_id_occurred_at',
      ]),
    )
    expect(indexNames).not.toContain('idx_sessions_github_id')
    expect(indexNames).not.toContain('idx_sessions_expires_at')
  })

  it('does not store a client secret', async () => {
    const result = await env.DB.prepare(
      `SELECT name
       FROM pragma_table_info('clients')`,
    ).all<{ name: string }>()
    const columnNames = result.results.map(({ name }) => name)

    expect(columnNames).not.toContain('client_secret_hash')
    expect(columnNames).not.toContain('client_secret')
  })

  it('records the migration only once when reapplied', async () => {
    await applyD1Migrations(env.DB, env.TEST_MIGRATIONS)

    const row = await env.DB.prepare(
      `SELECT COUNT(*) AS count
       FROM d1_migrations
       WHERE name = ?`,
    )
      .bind('0001_initial.sql')
      .first<{ count: number }>()

    expect(row?.count).toBe(1)
  })
})

describe('valid records', () => {
  it('stores a complete authentication data graph', async () => {
    await insertUser()
    await insertClientWithRedirect()

    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO oauth_states
           (upstream_state_hash, client_state, client_id, redirect_uri, nonce,
            code_challenge, code_challenge_method, provider, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        HASH_A,
        'client-state',
        'client-a',
        'https://client.example/callback',
        'nonce',
        'challenge',
        'S256',
        'github',
        NOW,
        NOW + 60,
      ),
      env.DB.prepare(
        `INSERT INTO auth_codes
           (code_hash, user_id, client_id, redirect_uri, nonce,
            code_challenge, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        HASH_B,
        USER_ID,
        'client-a',
        'https://client.example/callback',
        'nonce',
        'challenge',
        NOW,
        NOW + 60,
      ),
    ])

    expect(await countRows('oauth_states')).toBe(1)
    expect(await countRows('auth_codes')).toBe(1)
  })

  it('stores success and failure audit events without related records', async () => {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO auth_events
           (event_type, provider, user_id, github_id, github_login, client_id,
            redirect_uri, success, ip_address, user_agent, occurred_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        'callback',
        'github',
        null,
        '123',
        'octocat',
        'client-a',
        'https://client.example/callback',
        1,
        '203.0.113.10',
        'test-agent',
        NOW,
      ),
      env.DB.prepare(
        `INSERT INTO auth_events
           (event_type, success, reason, occurred_at)
         VALUES (?, ?, ?, ?)`,
      ).bind('token', 0, 'invalid_code', NOW),
    ])

    expect(await countRows('auth_events')).toBe(2)
  })
})

describe('uniqueness constraints', () => {
  it('rejects duplicate user and client primary keys', async () => {
    await insertUser()
    await insertClient()

    await expect(insertUser()).rejects.toThrow()
    await expect(insertClient()).rejects.toThrow()
  })

  it('rejects duplicate state and authorization code hashes', async () => {
    await insertUser()
    await insertClientWithRedirect()

    const stateStatement = env.DB.prepare(
      `INSERT INTO oauth_states
         (upstream_state_hash, client_state, client_id, redirect_uri, nonce,
          code_challenge, code_challenge_method, provider, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      HASH_A,
      'client-state',
      'client-a',
      'https://client.example/callback',
      'nonce',
      'challenge',
      'S256',
      'github',
      NOW,
      NOW + 60,
    )
    const codeStatement = env.DB.prepare(
      `INSERT INTO auth_codes
         (code_hash, user_id, client_id, redirect_uri, nonce,
          code_challenge, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      HASH_B,
      USER_ID,
      'client-a',
      'https://client.example/callback',
      'nonce',
      'challenge',
      NOW,
      NOW + 60,
    )

    await env.DB.batch([stateStatement, codeStatement])
    await expect(stateStatement.run()).rejects.toThrow()
    await expect(codeStatement.run()).rejects.toThrow()
  })

  it('rejects a duplicate redirect URI for the same client', async () => {
    await insertClientWithRedirect()

    await expect(insertRedirectUri()).rejects.toThrow()
  })

  it('allows the same redirect URI for different clients', async () => {
    await insertClientWithRedirect('client-a')
    await insertClientWithRedirect('client-b')

    expect(await countRows('allowed_redirect_uris')).toBe(2)
  })
})

describe('hash constraints', () => {
  const invalidHashes = [
    ['too short', 'a'.repeat(63)],
    ['uppercase', 'A'.repeat(64)],
    ['non-hex', `${'a'.repeat(63)}g`],
  ] as const

  it.each(invalidHashes)(
    'rejects a %s OAuth state hash',
    async (_caseName, hash) => {
      await insertClientWithRedirect()

      await expect(
        env.DB.prepare(
          `INSERT INTO oauth_states
             (upstream_state_hash, client_state, client_id, redirect_uri, nonce,
              code_challenge, code_challenge_method, provider, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
          .bind(
            hash,
            'client-state',
            'client-a',
            'https://client.example/callback',
            'nonce',
            'challenge',
            'S256',
            'github',
            NOW,
            NOW + 60,
          )
          .run(),
      ).rejects.toThrow()
    },
  )

  it.each(invalidHashes)(
    'rejects a %s authorization code hash',
    async (_caseName, hash) => {
      await insertUser()
      await insertClientWithRedirect()

      await expect(
        env.DB.prepare(
          `INSERT INTO auth_codes
             (code_hash, user_id, client_id, redirect_uri, nonce,
              code_challenge, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
          .bind(
            hash,
            USER_ID,
            'client-a',
            'https://client.example/callback',
            'nonce',
            'challenge',
            NOW,
            NOW + 60,
          )
          .run(),
      ).rejects.toThrow()
    },
  )

  it.each(invalidHashes)(
    'rejects a %s Google allowlist email hash',
    async (_caseName, hash) => {
      await insertUser()

      await expect(
        env.DB.prepare(
          `INSERT INTO google_login_allowlist
             (email_hash, pepper_version, user_id, created_at, disabled_at)
           VALUES (?, ?, ?, ?, ?)`,
        )
          .bind(hash, 1, USER_ID, NOW, null)
          .run(),
      ).rejects.toThrow()
    },
  )
})

describe('time and value constraints', () => {
  it('rejects expiration times that are not after creation', async () => {
    await insertUser()
    await insertClientWithRedirect()

    const statements = [
      env.DB.prepare(
        `INSERT INTO oauth_states
           (upstream_state_hash, client_state, client_id, redirect_uri, nonce,
            code_challenge, code_challenge_method, provider, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        HASH_A,
        'client-state',
        'client-a',
        'https://client.example/callback',
        'nonce',
        'challenge',
        'S256',
        'github',
        NOW,
        NOW,
      ),
      env.DB.prepare(
        `INSERT INTO auth_codes
           (code_hash, user_id, client_id, redirect_uri, nonce,
            code_challenge, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        HASH_B,
        USER_ID,
        'client-a',
        'https://client.example/callback',
        'nonce',
        'challenge',
        NOW,
        NOW,
      ),
    ]

    for (const statement of statements) {
      await expect(statement.run()).rejects.toThrow()
    }
  })

  it('rejects non-positive timestamps', async () => {
    await insertClient()

    const statements = [
      env.DB.prepare(
        `INSERT INTO users (id, created_at, updated_at)
         VALUES (?, ?, ?)`,
      ).bind('101', 0, NOW),
      env.DB.prepare(
        `INSERT INTO clients (client_id, created_at)
         VALUES (?, ?)`,
      ).bind('client-b', 0),
      env.DB.prepare(
        `INSERT INTO allowed_redirect_uris
           (client_id, redirect_uri, created_at)
         VALUES (?, ?, ?)`,
      ).bind('client-a', 'https://client.example/other', 0),
      env.DB.prepare(
        `INSERT INTO oauth_states
           (upstream_state_hash, client_state, client_id, redirect_uri, nonce,
            code_challenge, code_challenge_method, provider, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        HASH_A,
        'client-state',
        'client-a',
        'https://client.example/callback',
        'nonce',
        'challenge',
        'S256',
        'github',
        0,
        NOW,
      ),
      env.DB.prepare(
        `INSERT INTO auth_events (event_type, success, occurred_at)
         VALUES (?, ?, ?)`,
      ).bind('callback', 1, 0),
    ]

    for (const statement of statements) {
      await expect(statement.run()).rejects.toThrow()
    }
  })

  it('rejects empty required identifiers', async () => {
    await insertClient()

    const statements = [
      env.DB.prepare(
        `INSERT INTO users (id, created_at, updated_at)
         VALUES (?, ?, ?)`,
      ).bind('', NOW, NOW),
      env.DB.prepare(
        `INSERT INTO github_identities
           (github_id, user_id, created_at, updated_at)
         VALUES (?, ?, ?, ?)`,
      ).bind('', USER_ID, NOW, NOW),
      env.DB.prepare(
        `INSERT INTO clients (client_id, created_at)
         VALUES (?, ?)`,
      ).bind('', NOW),
      env.DB.prepare(
        `INSERT INTO allowed_redirect_uris
           (client_id, redirect_uri, created_at)
         VALUES (?, ?, ?)`,
      ).bind('client-a', '', NOW),
      env.DB.prepare(
        `INSERT INTO auth_events (event_type, success, occurred_at)
         VALUES (?, ?, ?)`,
      ).bind('', 1, NOW),
    ]

    for (const statement of statements) {
      await expect(statement.run()).rejects.toThrow()
    }
  })

  it('rejects invalid audit event values', async () => {
    const statements = [
      env.DB.prepare(
        `INSERT INTO auth_events (event_type, success, occurred_at)
         VALUES (?, ?, ?)`,
      ).bind('callback', 2, NOW),
      env.DB.prepare(
        `INSERT INTO auth_events (event_type, success, occurred_at)
         VALUES (?, ?, ?)`,
      ).bind('callback', 1, 0),
    ]

    for (const statement of statements) {
      await expect(statement.run()).rejects.toThrow()
    }
  })
})

describe('foreign keys and redirect URI matching', () => {
  it('rejects authorization codes for missing users', async () => {
    await insertClientWithRedirect()

    await expect(
      env.DB.prepare(
        `INSERT INTO auth_codes
           (code_hash, user_id, client_id, redirect_uri, nonce,
            code_challenge, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          HASH_B,
          'missing-user',
          'client-a',
          'https://client.example/callback',
          'nonce',
          'challenge',
          NOW,
          NOW + 60,
        )
        .run(),
    ).rejects.toThrow()
  })

  it('requires an exact client and redirect URI pair', async () => {
    await insertUser()
    await insertClientWithRedirect(
      'client-a',
      'https://client.example/callback',
    )
    await insertClientWithRedirect(
      'client-b',
      'https://other.example/callback',
    )

    const invalidPairs = [
      ['client-a', 'https://client.example/callback/extra'],
      ['client-a', 'https://other.example/callback'],
      ['missing-client', 'https://client.example/callback'],
    ] as const

    for (const [clientId, redirectUri] of invalidPairs) {
      await expect(
        env.DB.prepare(
          `INSERT INTO oauth_states
             (upstream_state_hash, client_state, client_id, redirect_uri, nonce,
              code_challenge, code_challenge_method, provider, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
          .bind(
            HASH_A,
            'client-state',
            clientId,
            redirectUri,
            'nonce',
            'challenge',
            'S256',
            'github',
            NOW,
            NOW + 60,
          )
          .run(),
      ).rejects.toThrow()

      await expect(
        env.DB.prepare(
          `INSERT INTO auth_codes
             (code_hash, user_id, client_id, redirect_uri, nonce,
              code_challenge, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
          .bind(
            HASH_B,
            USER_ID,
            clientId,
            redirectUri,
            'nonce',
            'challenge',
            NOW,
            NOW + 60,
          )
          .run(),
      ).rejects.toThrow()
    }
  })
})

describe('cascade deletion and audit retention', () => {
  it('deletes authorization codes with their user', async () => {
    await insertUser()
    await insertClientWithRedirect()
    await env.DB.prepare(
      `INSERT INTO auth_codes
         (code_hash, user_id, client_id, redirect_uri, nonce,
          code_challenge, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        HASH_B,
        USER_ID,
        'client-a',
        'https://client.example/callback',
        'nonce',
        'challenge',
        NOW,
        NOW + 60,
      )
      .run()

    await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(USER_ID).run()

    expect(await countRows('auth_codes')).toBe(0)
  })

  it('deletes redirect URIs, states, and codes with their client', async () => {
    await insertUser()
    await insertClientWithRedirect()
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO oauth_states
           (upstream_state_hash, client_state, client_id, redirect_uri, nonce,
            code_challenge, code_challenge_method, provider, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        HASH_A,
        'client-state',
        'client-a',
        'https://client.example/callback',
        'nonce',
        'challenge',
        'S256',
        'github',
        NOW,
        NOW + 60,
      ),
      env.DB.prepare(
        `INSERT INTO auth_codes
           (code_hash, user_id, client_id, redirect_uri, nonce,
            code_challenge, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        HASH_B,
        USER_ID,
        'client-a',
        'https://client.example/callback',
        'nonce',
        'challenge',
        NOW,
        NOW + 60,
      ),
    ])

    await env.DB.prepare('DELETE FROM clients WHERE client_id = ?')
      .bind('client-a')
      .run()

    expect(await countRows('allowed_redirect_uris')).toBe(0)
    expect(await countRows('oauth_states')).toBe(0)
    expect(await countRows('auth_codes')).toBe(0)
  })

  it('keeps audit events after related user and client deletion', async () => {
    await insertUser()
    await insertClient()
    await env.DB.prepare(
      `INSERT INTO auth_events
         (event_type, user_id, client_id, success, occurred_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
      .bind('callback', USER_ID, 'client-a', 1, NOW)
      .run()

    await env.DB.batch([
      env.DB.prepare('DELETE FROM users WHERE id = ?').bind(USER_ID),
      env.DB.prepare('DELETE FROM clients WHERE client_id = ?').bind(
        'client-a',
      ),
    ])

    expect(await countRows('auth_events')).toBe(1)
  })
})
