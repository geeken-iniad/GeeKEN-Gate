import {
  createExecutionContext,
  createScheduledController,
} from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { beforeEach, describe, expect, it } from 'vitest'

import { cleanupExpiredAuthData } from '../src/lib/cleanup'
import { scheduled } from '../src/index'

const CURRENT_TIME = 1_800_000_000
const SIXTY_DAYS_SECONDS = 60 * 24 * 60 * 60
const HASH_A = 'a'.repeat(64)
const HASH_B = 'b'.repeat(64)
const HASH_C = 'c'.repeat(64)
const REDIRECT_URI = 'https://client.example/callback'

async function insertCleanupFixtures(): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO users (id, created_at, updated_at)
       VALUES (?, ?, ?)`,
    ).bind('user-a', CURRENT_TIME - 100, CURRENT_TIME - 100),
    env.DB.prepare(
      `INSERT INTO clients (client_id, created_at)
       VALUES (?, ?)`,
    ).bind('client-a', CURRENT_TIME - 100),
    env.DB.prepare(
      `INSERT INTO allowed_redirect_uris
         (client_id, redirect_uri, created_at)
       VALUES (?, ?, ?)`,
    ).bind('client-a', REDIRECT_URI, CURRENT_TIME - 100),
  ])

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO oauth_states
         (upstream_state_hash, client_state, client_id, redirect_uri, nonce,
          code_challenge, code_challenge_method, provider, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      HASH_A,
      'state-a',
      'client-a',
      REDIRECT_URI,
      'nonce',
      'challenge',
      'S256',
      'github',
      CURRENT_TIME - 100,
      CURRENT_TIME - 1,
    ),
    env.DB.prepare(
      `INSERT INTO oauth_states
         (upstream_state_hash, client_state, client_id, redirect_uri, nonce,
          code_challenge, code_challenge_method, provider, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      HASH_B,
      'state-b',
      'client-a',
      REDIRECT_URI,
      'nonce',
      'challenge',
      'S256',
      'github',
      CURRENT_TIME - 100,
      CURRENT_TIME,
    ),
    env.DB.prepare(
      `INSERT INTO oauth_states
         (upstream_state_hash, client_state, client_id, redirect_uri, nonce,
          code_challenge, code_challenge_method, provider, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      HASH_C,
      'state-c',
      'client-a',
      REDIRECT_URI,
      'nonce',
      'challenge',
      'S256',
      'github',
      CURRENT_TIME - 100,
      CURRENT_TIME + 1,
    ),
    env.DB.prepare(
      `INSERT INTO auth_codes
         (code_hash, user_id, client_id, redirect_uri, nonce,
          code_challenge, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      HASH_A,
      'user-a',
      'client-a',
      REDIRECT_URI,
      'nonce',
      'challenge',
      CURRENT_TIME - 100,
      CURRENT_TIME - 1,
    ),
    env.DB.prepare(
      `INSERT INTO auth_codes
         (code_hash, user_id, client_id, redirect_uri, nonce,
          code_challenge, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      HASH_B,
      'user-a',
      'client-a',
      REDIRECT_URI,
      'nonce',
      'challenge',
      CURRENT_TIME - 100,
      CURRENT_TIME,
    ),
    env.DB.prepare(
      `INSERT INTO auth_codes
         (code_hash, user_id, client_id, redirect_uri, nonce,
          code_challenge, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      HASH_C,
      'user-a',
      'client-a',
      REDIRECT_URI,
      'nonce',
      'challenge',
      CURRENT_TIME - 100,
      CURRENT_TIME + 1,
    ),
    env.DB.prepare(
      `INSERT INTO access_tokens
         (token_hash, user_id, client_id, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).bind(HASH_A, 'user-a', 'client-a', CURRENT_TIME - 100, CURRENT_TIME - 1),
    env.DB.prepare(
      `INSERT INTO access_tokens
         (token_hash, user_id, client_id, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).bind(HASH_B, 'user-a', 'client-a', CURRENT_TIME - 100, CURRENT_TIME),
    env.DB.prepare(
      `INSERT INTO access_tokens
         (token_hash, user_id, client_id, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).bind(HASH_C, 'user-a', 'client-a', CURRENT_TIME - 100, CURRENT_TIME + 1),
    env.DB.prepare(
      `INSERT INTO refresh_tokens
         (token_hash, user_id, client_id, created_at, expires_at, revoked_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(
      HASH_A,
      'user-a',
      'client-a',
      CURRENT_TIME - 100,
      CURRENT_TIME - 1,
      null,
    ),
    env.DB.prepare(
      `INSERT INTO refresh_tokens
         (token_hash, user_id, client_id, created_at, expires_at, revoked_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(
      HASH_B,
      'user-a',
      'client-a',
      CURRENT_TIME - 100,
      CURRENT_TIME,
      null,
    ),
    env.DB.prepare(
      `INSERT INTO refresh_tokens
         (token_hash, user_id, client_id, created_at, expires_at, revoked_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(
      HASH_C,
      'user-a',
      'client-a',
      CURRENT_TIME - 100,
      CURRENT_TIME + 1,
      null,
    ),
    env.DB.prepare(
      `INSERT INTO auth_events (event_type, success, occurred_at)
       VALUES (?, ?, ?)`,
    ).bind('old', 1, CURRENT_TIME - SIXTY_DAYS_SECONDS - 1),
    env.DB.prepare(
      `INSERT INTO auth_events (event_type, success, occurred_at)
       VALUES (?, ?, ?)`,
    ).bind('boundary', 1, CURRENT_TIME - SIXTY_DAYS_SECONDS),
    env.DB.prepare(
      `INSERT INTO auth_events (event_type, success, occurred_at)
       VALUES (?, ?, ?)`,
    ).bind('recent', 1, CURRENT_TIME - SIXTY_DAYS_SECONDS + 1),
  ])
}

async function getHashes(
  table: string,
  column: string,
): Promise<string[]> {
  const result = await env.DB.prepare(
    `SELECT ${column} AS hash FROM ${table} ORDER BY ${column}`,
  ).all<{ hash: string }>()

  return result.results.map((row) => row.hash)
}

async function getEventTypes(): Promise<string[]> {
  const result = await env.DB.prepare(
    'SELECT event_type FROM auth_events ORDER BY occurred_at',
  ).all<{ event_type: string }>()

  return result.results.map((row) => row.event_type)
}

describe('cleanupExpiredAuthData', () => {
  beforeEach(async () => {
    await insertCleanupFixtures()
  })

  it('deletes expired credentials and audit events older than 60 days', async () => {
    await cleanupExpiredAuthData(env.DB, CURRENT_TIME)

    await expect(getHashes('oauth_states', 'upstream_state_hash')).resolves.toEqual([
      HASH_C,
    ])
    await expect(getHashes('auth_codes', 'code_hash')).resolves.toEqual([
      HASH_C,
    ])
    await expect(getHashes('access_tokens', 'token_hash')).resolves.toEqual([
      HASH_C,
    ])
    await expect(getHashes('refresh_tokens', 'token_hash')).resolves.toEqual([
      HASH_C,
    ])
    await expect(getEventTypes()).resolves.toEqual(['boundary', 'recent'])
  })

  it('is idempotent', async () => {
    await cleanupExpiredAuthData(env.DB, CURRENT_TIME)
    await cleanupExpiredAuthData(env.DB, CURRENT_TIME)

    await expect(getEventTypes()).resolves.toEqual(['boundary', 'recent'])
  })
})

describe('scheduled cleanup handler', () => {
  it('uses the scheduled event time as the cleanup boundary', async () => {
    await insertCleanupFixtures()
    const controller = createScheduledController({
      scheduledTime: CURRENT_TIME * 1000,
      cron: '0 3 * * *',
    })
    const executionContext = createExecutionContext()

    await scheduled(controller, env, executionContext)

    await expect(getHashes('oauth_states', 'upstream_state_hash')).resolves.toEqual([
      HASH_C,
    ])
    await expect(getHashes('auth_codes', 'code_hash')).resolves.toEqual([
      HASH_C,
    ])
    await expect(getHashes('access_tokens', 'token_hash')).resolves.toEqual([
      HASH_C,
    ])
    await expect(getHashes('refresh_tokens', 'token_hash')).resolves.toEqual([
      HASH_C,
    ])
    await expect(getEventTypes()).resolves.toEqual(['boundary', 'recent'])
  })
})
