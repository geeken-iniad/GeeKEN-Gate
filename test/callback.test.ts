import { env } from 'cloudflare:workers'
import { Hono } from 'hono'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { AppBindings } from '../src/lib/config'
import { hashAuthToken } from '../src/lib/crypto'
import { GitHubAuthError } from '../src/lib/github'
import { createCallbackHandler } from '../src/routes/callback'
import { allowingRateLimiter } from './rate-limit'
import {
  CLIENT_ID,
  CLIENT_STATE,
  CODE_CHALLENGE,
  GITHUB_CALLBACK_URL,
  GITHUB_ID,
  GITHUB_LOGIN,
  ISSUER,
  NONCE,
  NOW,
  REDIRECT_URI,
  TOKEN_HASH_SECRET,
  UPSTREAM_STATE,
  USER_ID,
  createBindings,
  insertClient,
  insertUser,
} from './oidc-helpers'

const GITHUB_CODE = 'github-code'

interface AuthCodeRow {
  code_hash: string
  user_id: string
  nonce: string
  code_challenge: string
}

interface AuthEventRow {
  event_type: string
  provider: string | null
  user_id: string | null
  github_id: string | null
  github_login: string | null
  client_id: string | null
  redirect_uri: string | null
  success: number
  reason: string | null
}

async function insertClientAndState(
  expiresAt = Math.floor(Date.now() / 1000) + 600,
): Promise<void> {
  await insertClient()

  const stateHash = await hashAuthToken(
    UPSTREAM_STATE,
    TOKEN_HASH_SECRET,
    'oauth-upstream-state',
  )

  await env.DB.prepare(
    `INSERT INTO oauth_states
       (upstream_state_hash, client_state, client_id, redirect_uri, nonce,
        code_challenge, code_challenge_method, provider, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      stateHash,
      CLIENT_STATE,
      CLIENT_ID,
      REDIRECT_URI,
      NONCE,
      CODE_CHALLENGE,
      'S256',
      'github',
      NOW,
      expiresAt,
    )
    .run()
}

function createTestApp(authenticate = vi.fn().mockResolvedValue({
  githubId: GITHUB_ID,
  githubLogin: GITHUB_LOGIN,
})) {
  const app = new Hono<{ Bindings: AppBindings }>()
  app.get('/callback', createCallbackHandler(authenticate))

  return { app, authenticate }
}

async function requestCallback(
  app: Hono<{ Bindings: AppBindings }>,
  query: Record<string, string> = {
    code: GITHUB_CODE,
    state: UPSTREAM_STATE,
  },
) {
  const url = new URL('https://auth.example.com/callback')

  for (const [name, value] of Object.entries(query)) {
    url.searchParams.set(name, value)
  }

  return app.request(
    url,
    {
      headers: {
        'CF-Connecting-IP': '203.0.113.10',
        'User-Agent': 'callback-test-agent',
      },
    },
    createBindings(),
  )
}

async function getAuthEvents(): Promise<AuthEventRow[]> {
  const result = await env.DB.prepare(
    `SELECT event_type, provider, user_id, github_id, github_login,
            client_id, redirect_uri, success, reason
     FROM auth_events
     ORDER BY id`,
  ).all<AuthEventRow>()

  return result.results
}

describe('GET /callback', () => {
  beforeEach(async () => {
    await insertClientAndState()
  })

  it('creates a user and identity, issues an auth code, and preserves client state', async () => {
    const { app } = createTestApp()
    const response = await requestCallback(app)

    expect(response.status).toBe(302)
    expect(response.headers.get('cache-control')).toBe('no-store')

    const location = new URL(response.headers.get('location') ?? '')
    const authCode = location.searchParams.get('code')

    expect(location.origin + location.pathname).toBe(
      'https://client.example/callback',
    )
    expect(location.searchParams.get('state')).toBe(CLIENT_STATE)
    expect(authCode).toMatch(/^[A-Za-z0-9_-]{43}$/)

    const identity = await env.DB.prepare(
      `SELECT github_id, user_id, github_login
       FROM github_identities
       WHERE github_id = ?`,
    )
      .bind(GITHUB_ID)
      .first<{ github_id: string; user_id: string; github_login: string }>()

    expect(identity).not.toBeNull()
    expect(identity!.github_login).toBe(GITHUB_LOGIN)

    const user = await env.DB.prepare(
      `SELECT id FROM users WHERE id = ?`,
    )
      .bind(identity!.user_id)
      .first<{ id: string }>()

    expect(user).not.toBeNull()

    const storedCode = await env.DB.prepare(
      `SELECT code_hash, user_id, nonce, code_challenge
       FROM auth_codes`,
    ).first<AuthCodeRow>()

    expect(storedCode).not.toBeNull()
    expect(storedCode!.user_id).toBe(identity!.user_id)
    expect(storedCode!.nonce).toBe(NONCE)
    expect(storedCode!.code_challenge).toBe(CODE_CHALLENGE)
    await expect(
      hashAuthToken(authCode ?? '', TOKEN_HASH_SECRET, 'auth-code'),
    ).resolves.toBe(storedCode!.code_hash)

    const events = await getAuthEvents()
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      event_type: 'callback',
      provider: 'github',
      github_id: GITHUB_ID,
      github_login: GITHUB_LOGIN,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      success: 1,
    })
  })

  it('updates an existing identity login', async () => {
    await insertUser(USER_ID)
    await env.DB.prepare(
      `UPDATE github_identities SET github_login = ? WHERE github_id = ?`,
    )
      .bind('old-login', GITHUB_ID)
      .run()

    const { app } = createTestApp()
    const response = await requestCallback(app)

    expect(response.status).toBe(302)

    const identity = await env.DB.prepare(
      `SELECT github_login, updated_at
       FROM github_identities
       WHERE github_id = ?`,
    )
      .bind(GITHUB_ID)
      .first<{ github_login: string; updated_at: number }>()

    expect(identity?.github_login).toBe(GITHUB_LOGIN)
    expect(identity?.updated_at).toBeGreaterThan(NOW)
  })

  it('rejects a reused state before calling GitHub', async () => {
    const { app, authenticate } = createTestApp()

    expect((await requestCallback(app)).status).toBe(302)
    const secondResponse = await requestCallback(app)

    expect(secondResponse.status).toBe(400)
    await expect(secondResponse.json()).resolves.toEqual({
      error: 'invalid_request',
    })
    expect(authenticate).toHaveBeenCalledTimes(1)

    const events = await getAuthEvents()
    expect(events).toHaveLength(2)
    expect(events[1]).toMatchObject({
      success: 0,
      reason: 'invalid_state',
    })
  })

  it('rejects an expired state before calling GitHub', async () => {
    await env.DB.prepare('UPDATE oauth_states SET expires_at = ?')
      .bind(Math.floor(Date.now() / 1000) - 1)
      .run()
    const { app, authenticate } = createTestApp()

    const response = await requestCallback(app)

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({
      error: 'invalid_request',
    })
    expect(authenticate).not.toHaveBeenCalled()
  })

  it.each([
    ['missing code', { state: UPSTREAM_STATE }],
    ['missing state', { code: GITHUB_CODE }],
  ])('rejects %s without consuming the state', async (_caseName, query) => {
    const { app, authenticate } = createTestApp()

    const response = await requestCallback(app, query)

    expect(response.status).toBe(400)
    expect(authenticate).not.toHaveBeenCalled()

    const stateCount = await env.DB.prepare(
      'SELECT COUNT(*) AS count FROM oauth_states',
    ).first<{ count: number }>()
    expect(stateCount?.count).toBe(1)
  })

  it('redirects a GitHub authentication failure without creating credentials', async () => {
    const authenticate = vi
      .fn()
      .mockRejectedValue(new GitHubAuthError('membership_not_active'))
    const { app } = createTestApp(authenticate)

    const response = await requestCallback(app)

    expect(response.status).toBe(302)
    const location = new URL(response.headers.get('location') ?? '')
    expect(location.origin + location.pathname).toBe(
      'https://client.example/callback',
    )
    expect(location.searchParams.get('state')).toBe(CLIENT_STATE)
    expect(location.searchParams.get('error')).toBe('access_denied')

    const events = await getAuthEvents()
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      success: 0,
      reason: 'membership_not_active',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
    })
  })

  it('rejects a frozen identity without creating credentials', async () => {
    await insertUser(USER_ID)
    await env.DB.prepare(
      `UPDATE github_identities
       SET frozen_at = ?, freeze_reason = ?
       WHERE github_id = ?`,
    )
      .bind(NOW, 'manual freeze', GITHUB_ID)
      .run()

    const { app } = createTestApp()
    const response = await requestCallback(app)

    expect(response.status).toBe(302)
    const location = new URL(response.headers.get('location') ?? '')
    expect(location.searchParams.get('error')).toBe('access_denied')
    expect(location.searchParams.get('state')).toBe(CLIENT_STATE)

    const events = await getAuthEvents()
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      success: 0,
      reason: 'frozen_user',
      github_id: GITHUB_ID,
      github_login: GITHUB_LOGIN,
    })
  })

  it('does not store callback secrets in audit events', async () => {
    const authenticate = vi
      .fn()
      .mockRejectedValue(new GitHubAuthError('token_exchange_failed'))
    const { app } = createTestApp(authenticate)

    await requestCallback(app)

    const serializedEvents = JSON.stringify(await getAuthEvents())
    expect(serializedEvents).not.toContain(GITHUB_CODE)
    expect(serializedEvents).not.toContain(UPSTREAM_STATE)
    expect(serializedEvents).not.toContain('github-client-secret')
  })
})
