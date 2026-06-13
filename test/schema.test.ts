import { applyD1Migrations } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { describe, expect, it } from 'vitest'

const NOW = 1_700_000_000
const HASH_A = 'a'.repeat(64)
const HASH_B = 'b'.repeat(64)

async function insertUser(githubId = '100', githubLogin = 'octocat') {
  await env.DB.prepare(
    `INSERT INTO users (github_id, github_login, created_at, updated_at)
     VALUES (?, ?, ?, ?)`,
  )
    .bind(githubId, githubLogin, NOW, NOW)
    .run()
}

async function insertClient(clientId = 'client-a') {
  await env.DB.prepare(
    `INSERT INTO clients (client_id, client_secret_hash, created_at)
     VALUES (?, ?, ?)`,
  )
    .bind(clientId, HASH_A, NOW)
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
        'frozen_users',
        'clients',
        'allowed_redirect_uris',
        'sessions',
        'oauth_states',
        'auth_codes',
        'auth_events',
      ]),
    )
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
        'idx_sessions_github_id',
        'idx_sessions_expires_at',
        'idx_oauth_states_expires_at',
        'idx_auth_codes_github_id',
        'idx_auth_codes_expires_at',
        'idx_auth_events_occurred_at',
        'idx_auth_events_event_type_occurred_at',
        'idx_auth_events_github_id_occurred_at',
        'idx_auth_events_client_id_occurred_at',
      ]),
    )
  })

  it('stores only the client secret hash', async () => {
    const result = await env.DB.prepare(
      `SELECT name
       FROM pragma_table_info('clients')`,
    ).all<{ name: string }>()
    const columnNames = result.results.map(({ name }) => name)

    expect(columnNames).toContain('client_secret_hash')
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
        `INSERT INTO sessions
           (session_hash, github_id, created_at, expires_at)
         VALUES (?, ?, ?, ?)`,
      ).bind(HASH_A, '100', NOW, NOW + 60),
      env.DB.prepare(
        `INSERT INTO oauth_states
           (state_hash, client_id, redirect_uri, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).bind(
        HASH_A,
        'client-a',
        'https://client.example/callback',
        NOW,
        NOW + 60,
      ),
      env.DB.prepare(
        `INSERT INTO auth_codes
           (code_hash, github_id, client_id, redirect_uri, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        HASH_B,
        '100',
        'client-a',
        'https://client.example/callback',
        NOW,
        NOW + 60,
      ),
    ])

    expect(await countRows('sessions')).toBe(1)
    expect(await countRows('oauth_states')).toBe(1)
    expect(await countRows('auth_codes')).toBe(1)
  })

  it('freezes a GitHub ID that has not logged in', async () => {
    await env.DB.prepare(
      `INSERT INTO frozen_users (github_id, frozen_at, reason)
       VALUES (?, ?, ?)`,
    )
      .bind('999', NOW, 'manual freeze')
      .run()

    expect(await countRows('frozen_users')).toBe(1)
  })

  it('stores success and failure audit events without related records', async () => {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO auth_events
           (event_type, github_id, github_login, client_id, redirect_uri,
            success, ip_address, user_agent, occurred_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        'callback',
        'missing-user',
        'octocat',
        'missing-client',
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
      ).bind('exchange', 0, 'invalid_code', NOW),
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

  it('rejects duplicate session, state, and authorization code hashes', async () => {
    await insertUser()
    await insertClientWithRedirect()
    const statements = [
      env.DB.prepare(
        `INSERT INTO sessions
           (session_hash, github_id, created_at, expires_at)
         VALUES (?, ?, ?, ?)`,
      ).bind(HASH_A, '100', NOW, NOW + 60),
      env.DB.prepare(
        `INSERT INTO oauth_states
           (state_hash, client_id, redirect_uri, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).bind(
        HASH_A,
        'client-a',
        'https://client.example/callback',
        NOW,
        NOW + 60,
      ),
      env.DB.prepare(
        `INSERT INTO auth_codes
           (code_hash, github_id, client_id, redirect_uri, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        HASH_B,
        '100',
        'client-a',
        'https://client.example/callback',
        NOW,
        NOW + 60,
      ),
    ]

    await env.DB.batch(statements)

    for (const statement of statements) {
      await expect(statement.run()).rejects.toThrow()
    }
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
    'rejects a %s client secret hash',
    async (_caseName, hash) => {
      await expect(
        env.DB.prepare(
          `INSERT INTO clients
             (client_id, client_secret_hash, created_at)
           VALUES (?, ?, ?)`,
        )
          .bind('client-a', hash, NOW)
          .run(),
      ).rejects.toThrow()
    },
  )

  it.each(invalidHashes)(
    'rejects a %s session hash',
    async (_caseName, hash) => {
      await insertUser()

      await expect(
        env.DB.prepare(
          `INSERT INTO sessions
             (session_hash, github_id, created_at, expires_at)
           VALUES (?, ?, ?, ?)`,
        )
          .bind(hash, '100', NOW, NOW + 60)
          .run(),
      ).rejects.toThrow()
    },
  )

  it.each(invalidHashes)(
    'rejects a %s OAuth state hash',
    async (_caseName, hash) => {
      await insertClientWithRedirect()

      await expect(
        env.DB.prepare(
          `INSERT INTO oauth_states
             (state_hash, client_id, redirect_uri, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?)`,
        )
          .bind(
            hash,
            'client-a',
            'https://client.example/callback',
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
             (code_hash, github_id, client_id, redirect_uri, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
          .bind(
            hash,
            '100',
            'client-a',
            'https://client.example/callback',
            NOW,
            NOW + 60,
          )
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
        `INSERT INTO sessions
           (session_hash, github_id, created_at, expires_at)
         VALUES (?, ?, ?, ?)`,
      ).bind(HASH_A, '100', NOW, NOW),
      env.DB.prepare(
        `INSERT INTO oauth_states
           (state_hash, client_id, redirect_uri, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).bind(
        HASH_A,
        'client-a',
        'https://client.example/callback',
        NOW,
        NOW,
      ),
      env.DB.prepare(
        `INSERT INTO auth_codes
           (code_hash, github_id, client_id, redirect_uri, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        HASH_B,
        '100',
        'client-a',
        'https://client.example/callback',
        NOW,
        NOW,
      ),
    ]

    for (const statement of statements) {
      await expect(statement.run()).rejects.toThrow()
    }
  })

  it('rejects a disabled time before client creation', async () => {
    await expect(
      env.DB.prepare(
        `INSERT INTO clients
           (client_id, client_secret_hash, created_at, disabled_at)
         VALUES (?, ?, ?, ?)`,
      )
        .bind('client-a', HASH_A, NOW, NOW - 1)
        .run(),
    ).rejects.toThrow()
  })

  it('rejects non-positive timestamps', async () => {
    await insertUser()
    await insertClientWithRedirect()

    const statements = [
      env.DB.prepare(
        `INSERT INTO users
           (github_id, github_login, created_at, updated_at)
         VALUES (?, ?, ?, ?)`,
      ).bind('101', 'hubot', 0, NOW),
      env.DB.prepare(
        `INSERT INTO frozen_users (github_id, frozen_at)
         VALUES (?, ?)`,
      ).bind('999', 0),
      env.DB.prepare(
        `INSERT INTO clients
           (client_id, client_secret_hash, created_at)
         VALUES (?, ?, ?)`,
      ).bind('client-b', HASH_B, 0),
      env.DB.prepare(
        `INSERT INTO allowed_redirect_uris
           (client_id, redirect_uri, created_at)
         VALUES (?, ?, ?)`,
      ).bind('client-a', 'https://client.example/other', 0),
      env.DB.prepare(
        `INSERT INTO sessions
           (session_hash, github_id, created_at, expires_at)
         VALUES (?, ?, ?, ?)`,
      ).bind(HASH_A, '100', 0, NOW),
      env.DB.prepare(
        `INSERT INTO oauth_states
           (state_hash, client_id, redirect_uri, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).bind(
        HASH_A,
        'client-a',
        'https://client.example/callback',
        0,
        NOW,
      ),
      env.DB.prepare(
        `INSERT INTO auth_codes
           (code_hash, github_id, client_id, redirect_uri, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        HASH_B,
        '100',
        'client-a',
        'https://client.example/callback',
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

  it('rejects empty required identifiers and labels', async () => {
    await insertClient()

    const statements = [
      env.DB.prepare(
        `INSERT INTO users
           (github_id, github_login, created_at, updated_at)
         VALUES (?, ?, ?, ?)`,
      ).bind('', 'octocat', NOW, NOW),
      env.DB.prepare(
        `INSERT INTO users
           (github_id, github_login, created_at, updated_at)
         VALUES (?, ?, ?, ?)`,
      ).bind('100', '', NOW, NOW),
      env.DB.prepare(
        `INSERT INTO frozen_users (github_id, frozen_at)
         VALUES (?, ?)`,
      ).bind('', NOW),
      env.DB.prepare(
        `INSERT INTO clients
           (client_id, client_secret_hash, created_at)
         VALUES (?, ?, ?)`,
      ).bind('', HASH_A, NOW),
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
  it('rejects sessions and authorization codes for missing users', async () => {
    await insertClientWithRedirect()

    await expect(
      env.DB.prepare(
        `INSERT INTO sessions
           (session_hash, github_id, created_at, expires_at)
         VALUES (?, ?, ?, ?)`,
      )
        .bind(HASH_A, 'missing-user', NOW, NOW + 60)
        .run(),
    ).rejects.toThrow()

    await expect(
      env.DB.prepare(
        `INSERT INTO auth_codes
           (code_hash, github_id, client_id, redirect_uri, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          HASH_B,
          'missing-user',
          'client-a',
          'https://client.example/callback',
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
             (state_hash, client_id, redirect_uri, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?)`,
        )
          .bind(HASH_A, clientId, redirectUri, NOW, NOW + 60)
          .run(),
      ).rejects.toThrow()

      await expect(
        env.DB.prepare(
          `INSERT INTO auth_codes
             (code_hash, github_id, client_id, redirect_uri, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
          .bind(
            HASH_B,
            '100',
            clientId,
            redirectUri,
            NOW,
            NOW + 60,
          )
          .run(),
      ).rejects.toThrow()
    }
  })
})

describe('cascade deletion and audit retention', () => {
  it('deletes sessions and authorization codes with their user', async () => {
    await insertUser()
    await insertClientWithRedirect()
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO sessions
           (session_hash, github_id, created_at, expires_at)
         VALUES (?, ?, ?, ?)`,
      ).bind(HASH_A, '100', NOW, NOW + 60),
      env.DB.prepare(
        `INSERT INTO auth_codes
           (code_hash, github_id, client_id, redirect_uri, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        HASH_B,
        '100',
        'client-a',
        'https://client.example/callback',
        NOW,
        NOW + 60,
      ),
    ])

    await env.DB.prepare('DELETE FROM users WHERE github_id = ?')
      .bind('100')
      .run()

    expect(await countRows('sessions')).toBe(0)
    expect(await countRows('auth_codes')).toBe(0)
  })

  it('deletes redirect URIs, states, and codes with their client', async () => {
    await insertUser()
    await insertClientWithRedirect()
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO oauth_states
           (state_hash, client_id, redirect_uri, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).bind(
        HASH_A,
        'client-a',
        'https://client.example/callback',
        NOW,
        NOW + 60,
      ),
      env.DB.prepare(
        `INSERT INTO auth_codes
           (code_hash, github_id, client_id, redirect_uri, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).bind(
        HASH_B,
        '100',
        'client-a',
        'https://client.example/callback',
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
         (event_type, github_id, client_id, success, occurred_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
      .bind('callback', '100', 'client-a', 1, NOW)
      .run()

    await env.DB.batch([
      env.DB.prepare('DELETE FROM users WHERE github_id = ?').bind('100'),
      env.DB.prepare('DELETE FROM clients WHERE client_id = ?').bind(
        'client-a',
      ),
    ])

    expect(await countRows('auth_events')).toBe(1)
  })
})
