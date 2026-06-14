import { env } from 'cloudflare:workers'
import { Hono } from 'hono'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { AppBindings } from '../src/lib/config'
import { hashAuthToken } from '../src/lib/crypto'
import { GitHubAuthError } from '../src/lib/github'
import { createCallbackHandler } from '../src/routes/callback'
import { allowingRateLimiter } from './rate-limit'

const NOW = 1_700_000_000
const CLIENT_ID = 'client-a'
const REDIRECT_URI = 'https://client.example/callback?source=login'
const SESSION_SECRET = 's'.repeat(32)
const OAUTH_STATE = 'oauth-state-value'
const GITHUB_CODE = 'github-code'
const GITHUB_USER = {
  githubId: '123456',
  githubLogin: 'octocat',
}

interface StoredCredential {
  hash: string
  created_at: number
  expires_at: number
}

interface AuthEventRow {
  event_type: string
  github_id: string | null
  github_login: string | null
  client_id: string | null
  redirect_uri: string | null
  success: number
  reason: string | null
  ip_address: string | null
  user_agent: string | null
}

function createBindings(): AppBindings {
  return {
    DB: env.DB,
    PUBLIC_RATE_LIMITER: allowingRateLimiter,
    CLIENT_RATE_LIMITER: allowingRateLimiter,
    GITHUB_CLIENT_ID: 'github-client-id',
    GITHUB_CLIENT_SECRET: 'github-client-secret',
    GITHUB_ORG: 'example-org',
    GITHUB_CALLBACK_URL: 'https://auth.example.com/callback',
    SESSION_SECRET,
  }
}

async function insertClientAndState(
  expiresAt = Math.floor(Date.now() / 1000) + 600,
): Promise<void> {
  const stateHash = await hashAuthToken(
    OAUTH_STATE,
    SESSION_SECRET,
    'oauth-state',
  )

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO clients
         (client_id, client_secret_hash, created_at)
       VALUES (?, ?, ?)`,
    ).bind(CLIENT_ID, 'a'.repeat(64), NOW),
    env.DB.prepare(
      `INSERT INTO allowed_redirect_uris
         (client_id, redirect_uri, created_at)
       VALUES (?, ?, ?)`,
    ).bind(CLIENT_ID, REDIRECT_URI, NOW),
    env.DB.prepare(
      `INSERT INTO oauth_states
         (state_hash, client_id, redirect_uri, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).bind(stateHash, CLIENT_ID, REDIRECT_URI, NOW, expiresAt),
  ])
}

function createTestApp(authenticate = vi.fn().mockResolvedValue(GITHUB_USER)) {
  const app = new Hono<{ Bindings: AppBindings }>()
  app.get('/callback', createCallbackHandler(authenticate))

  return { app, authenticate }
}

async function requestCallback(
  app: Hono<{ Bindings: AppBindings }>,
  query: Record<string, string> = {
    code: GITHUB_CODE,
    state: OAUTH_STATE,
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

async function countRows(table: string): Promise<number> {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS count FROM ${table}`,
  ).first<{ count: number }>()

  return row?.count ?? 0
}

async function getAuthEvents(): Promise<AuthEventRow[]> {
  const result = await env.DB.prepare(
    `SELECT event_type, github_id, github_login, client_id, redirect_uri,
            success, reason, ip_address, user_agent
     FROM auth_events
     ORDER BY id`,
  ).all<AuthEventRow>()

  return result.results
}

describe('GET /callback', () => {
  beforeEach(async () => {
    await insertClientAndState()
  })

  it('creates credentials and redirects an active organization member', async () => {
    const { app, authenticate } = createTestApp()
    const beforeRequest = Math.floor(Date.now() / 1000)
    const response = await requestCallback(app)
    const afterRequest = Math.floor(Date.now() / 1000)

    expect(response.status).toBe(302)
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(authenticate).toHaveBeenCalledWith(GITHUB_CODE, {
      clientId: 'github-client-id',
      clientSecret: 'github-client-secret',
      callbackUrl: new URL('https://auth.example.com/callback'),
      organization: 'example-org',
    })

    const location = new URL(response.headers.get('location') ?? '')
    const authCode = location.searchParams.get('code')
    expect(location.origin + location.pathname).toBe(
      'https://client.example/callback',
    )
    expect(location.searchParams.get('source')).toBe('login')
    expect(authCode).toMatch(/^[A-Za-z0-9_-]{43}$/)

    const setCookie = response.headers.get('set-cookie') ?? ''
    const session = /^giken_session=([^;]+)/.exec(setCookie)?.[1]
    expect(session).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(setCookie).toContain('Max-Age=604800')
    expect(setCookie).toContain('Path=/')
    expect(setCookie).toContain('HttpOnly')
    expect(setCookie).toContain('Secure')
    expect(setCookie).toContain('SameSite=Lax')

    const user = await env.DB.prepare(
      `SELECT github_id, github_login, created_at, updated_at
       FROM users`,
    ).first<{
      github_id: string
      github_login: string
      created_at: number
      updated_at: number
    }>()
    expect(user).toMatchObject({
      github_id: GITHUB_USER.githubId,
      github_login: GITHUB_USER.githubLogin,
    })
    expect(user?.created_at).toBeGreaterThanOrEqual(beforeRequest)
    expect(user?.created_at).toBeLessThanOrEqual(afterRequest)
    expect(user?.updated_at).toBe(user?.created_at)

    const storedSession = await env.DB.prepare(
      `SELECT session_hash AS hash, created_at, expires_at
       FROM sessions`,
    ).first<StoredCredential>()
    const storedCode = await env.DB.prepare(
      `SELECT code_hash AS hash, created_at, expires_at
       FROM auth_codes`,
    ).first<StoredCredential>()

    expect(storedSession).not.toBeNull()
    expect(storedCode).not.toBeNull()
    expect(storedSession!.expires_at - storedSession!.created_at).toBe(
      7 * 24 * 60 * 60,
    )
    expect(storedCode!.expires_at - storedCode!.created_at).toBe(2 * 60)
    expect(storedSession!.hash).not.toBe(session)
    expect(storedCode!.hash).not.toBe(authCode)
    await expect(
      hashAuthToken(session ?? '', SESSION_SECRET, 'session'),
    ).resolves.toBe(storedSession!.hash)
    await expect(
      hashAuthToken(authCode ?? '', SESSION_SECRET, 'auth-code'),
    ).resolves.toBe(storedCode!.hash)
    expect(await countRows('oauth_states')).toBe(0)

    await expect(getAuthEvents()).resolves.toEqual([
      {
        event_type: 'callback',
        github_id: GITHUB_USER.githubId,
        github_login: GITHUB_USER.githubLogin,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        success: 1,
        reason: null,
        ip_address: '203.0.113.10',
        user_agent: 'callback-test-agent',
      },
    ])
  })

  it('updates an existing user login', async () => {
    await env.DB.prepare(
      `INSERT INTO users
         (github_id, github_login, created_at, updated_at)
       VALUES (?, ?, ?, ?)`,
    )
      .bind(GITHUB_USER.githubId, 'old-login', NOW, NOW)
      .run()
    const { app } = createTestApp()

    const response = await requestCallback(app)

    expect(response.status).toBe(302)
    const user = await env.DB.prepare(
      `SELECT github_login, created_at, updated_at
       FROM users
       WHERE github_id = ?`,
    )
      .bind(GITHUB_USER.githubId)
      .first<{
        github_login: string
        created_at: number
        updated_at: number
      }>()
    expect(user?.github_login).toBe(GITHUB_USER.githubLogin)
    expect(user?.created_at).toBe(NOW)
    expect(user?.updated_at).toBeGreaterThan(NOW)
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
    expect(await countRows('sessions')).toBe(1)
    expect(await countRows('auth_codes')).toBe(1)

    const events = await getAuthEvents()
    expect(events).toHaveLength(2)
    expect(events[1]).toMatchObject({
      success: 0,
      reason: 'invalid_state',
      client_id: null,
      redirect_uri: null,
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
    expect(await countRows('sessions')).toBe(0)
    expect(await countRows('auth_codes')).toBe(0)
  })

  it.each([
    ['missing code', { state: OAUTH_STATE }],
    ['missing state', { code: GITHUB_CODE }],
  ])('rejects %s without consuming the state', async (_caseName, query) => {
    const { app, authenticate } = createTestApp()

    const response = await requestCallback(app, query)

    expect(response.status).toBe(400)
    expect(authenticate).not.toHaveBeenCalled()
    expect(await countRows('oauth_states')).toBe(1)
    await expect(getAuthEvents()).resolves.toEqual([
      expect.objectContaining({
        success: 0,
        reason: 'invalid_request',
      }),
    ])
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
    expect(location.searchParams.get('source')).toBe('login')
    expect(location.searchParams.get('error')).toBe('access_denied')
    expect(response.headers.get('set-cookie')).toBeNull()
    expect(await countRows('oauth_states')).toBe(0)
    expect(await countRows('users')).toBe(0)
    expect(await countRows('sessions')).toBe(0)
    expect(await countRows('auth_codes')).toBe(0)
    await expect(getAuthEvents()).resolves.toEqual([
      expect.objectContaining({
        success: 0,
        reason: 'membership_not_active',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
      }),
    ])
  })

  it('rejects a frozen user without creating credentials', async () => {
    await env.DB.prepare(
      `INSERT INTO frozen_users (github_id, frozen_at, reason)
       VALUES (?, ?, ?)`,
    )
      .bind(GITHUB_USER.githubId, NOW, 'manual freeze')
      .run()
    const { app } = createTestApp()

    const response = await requestCallback(app)

    expect(response.status).toBe(302)
    expect(
      new URL(response.headers.get('location') ?? '').searchParams.get('error'),
    ).toBe('access_denied')
    expect(await countRows('users')).toBe(0)
    expect(await countRows('sessions')).toBe(0)
    expect(await countRows('auth_codes')).toBe(0)
    await expect(getAuthEvents()).resolves.toEqual([
      expect.objectContaining({
        github_id: GITHUB_USER.githubId,
        github_login: GITHUB_USER.githubLogin,
        success: 0,
        reason: 'frozen_user',
      }),
    ])
  })

  it('does not store callback secrets in the audit event', async () => {
    const authenticate = vi
      .fn()
      .mockRejectedValue(new GitHubAuthError('token_exchange_failed'))
    const { app } = createTestApp(authenticate)

    await requestCallback(app)

    const serializedEvents = JSON.stringify(await getAuthEvents())
    expect(serializedEvents).not.toContain(GITHUB_CODE)
    expect(serializedEvents).not.toContain(OAUTH_STATE)
    expect(serializedEvents).not.toContain('github-client-secret')
  })
})
