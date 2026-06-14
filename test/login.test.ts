import { env } from 'cloudflare:workers'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { AppBindings } from '../src/lib/config'
import { hashAuthToken } from '../src/lib/crypto'
import { app } from '../src/index'
import { allowingRateLimiter } from './rate-limit'

const NOW = 1_700_000_000
const CLIENT_SECRET_HASH = 'a'.repeat(64)
const CLIENT_ID = 'client-a'
const REDIRECT_URI = 'https://client.example/callback'
const SESSION_SECRET = 'test-session-secret'

afterEach(() => {
  vi.restoreAllMocks()
})

interface OAuthStateRow {
  state_hash: string
  client_id: string
  redirect_uri: string
  created_at: number
  expires_at: number
}

function createBindings(
  overrides: Partial<AppBindings> = {},
): AppBindings {
  return {
    DB: env.DB,
    PUBLIC_RATE_LIMITER: allowingRateLimiter,
    CLIENT_RATE_LIMITER: allowingRateLimiter,
    GITHUB_CLIENT_ID: 'github-client-id',
    GITHUB_CLIENT_SECRET: 'github-client-secret',
    GITHUB_ORG: 'example-org',
    GITHUB_CALLBACK_URL: 'https://auth.example.com/callback',
    SESSION_SECRET,
    ...overrides,
  }
}

async function insertClient(options: { disabled?: boolean } = {}) {
  await env.DB.prepare(
    `INSERT INTO clients
       (client_id, client_secret_hash, created_at, disabled_at)
     VALUES (?, ?, ?, ?)`,
  )
    .bind(
      CLIENT_ID,
      CLIENT_SECRET_HASH,
      NOW,
      options.disabled ? NOW + 1 : null,
    )
    .run()

  await env.DB.prepare(
    `INSERT INTO allowed_redirect_uris
       (client_id, redirect_uri, created_at)
     VALUES (?, ?, ?)`,
  )
    .bind(CLIENT_ID, REDIRECT_URI, NOW)
    .run()
}

async function requestLogin(
  query: Record<string, string> = {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
  },
  bindingOverrides: Partial<AppBindings> = {},
  headers: HeadersInit = {},
) {
  const url = new URL('https://auth.example.com/login')

  for (const [name, value] of Object.entries(query)) {
    url.searchParams.set(name, value)
  }

  return app.request(
    url,
    {
      headers,
    },
    createBindings(bindingOverrides),
  )
}

async function getOAuthStates(): Promise<OAuthStateRow[]> {
  const result = await env.DB.prepare(
    `SELECT state_hash, client_id, redirect_uri, created_at, expires_at
     FROM oauth_states`,
  ).all<OAuthStateRow>()

  return result.results
}

describe('GET /login', () => {
  beforeEach(async () => {
    await insertClient()
  })

  it('stores a hashed state and redirects to GitHub authorization', async () => {
    const beforeRequest = Math.floor(Date.now() / 1000)
    const response = await requestLogin()
    const afterRequest = Math.floor(Date.now() / 1000)

    expect(response.status).toBe(302)
    expect(response.headers.get('cache-control')).toBe('no-store')

    const location = new URL(response.headers.get('location') ?? '')
    const state = location.searchParams.get('state')

    expect(location.origin + location.pathname).toBe(
      'https://github.com/login/oauth/authorize',
    )
    expect(location.searchParams.get('client_id')).toBe('github-client-id')
    expect(location.searchParams.get('redirect_uri')).toBe(
      'https://auth.example.com/callback',
    )
    expect(location.searchParams.get('scope')).toBe('read:org')
    expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/)

    const rows = await getOAuthStates()
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
    })
    expect(rows[0].created_at).toBeGreaterThanOrEqual(beforeRequest)
    expect(rows[0].created_at).toBeLessThanOrEqual(afterRequest)
    expect(rows[0].expires_at - rows[0].created_at).toBe(10 * 60)
    expect(rows[0].state_hash).not.toBe(state)
    await expect(
      hashAuthToken(state ?? '', SESSION_SECRET, 'oauth-state'),
    ).resolves.toBe(rows[0].state_hash)
  })

  it('creates a different state for each login request', async () => {
    const firstResponse = await requestLogin()
    const secondResponse = await requestLogin()
    const firstState = new URL(
      firstResponse.headers.get('location') ?? '',
    ).searchParams.get('state')
    const secondState = new URL(
      secondResponse.headers.get('location') ?? '',
    ).searchParams.get('state')

    expect(firstState).not.toBe(secondState)
    await expect(getOAuthStates()).resolves.toHaveLength(2)
  })

  it('rejects a rate-limited IP before storing an OAuth state', async () => {
    const limiter = {
      limit: vi.fn().mockResolvedValue({ success: false }),
    } as RateLimit
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const response = await requestLogin(
      undefined,
      { PUBLIC_RATE_LIMITER: limiter },
      {
        'CF-Connecting-IP': '203.0.113.30',
        'CF-Ray': 'login-ray',
      },
    )

    expect(response.status).toBe(429)
    expect(response.headers.get('retry-after')).toBe('60')
    await expect(response.json()).resolves.toEqual({
      error: 'rate_limited',
    })
    expect(limiter.limit).toHaveBeenCalledWith({
      key: 'login:ip:203.0.113.30',
    })
    await expect(getOAuthStates()).resolves.toHaveLength(0)
    expect(warn).toHaveBeenCalledWith({
      event: 'rate_limited',
      route: '/login',
      scope: 'ip',
      cfRay: 'login-ray',
      clientId: null,
    })
  })

  it('continues login when the rate limiter throws', async () => {
    const limiter = {
      limit: vi.fn().mockRejectedValue(new Error('limiter unavailable')),
    } as RateLimit
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const response = await requestLogin(
      undefined,
      { PUBLIC_RATE_LIMITER: limiter },
      {
        'CF-Connecting-IP': '203.0.113.30',
        'CF-Ray': 'login-ray',
      },
    )

    expect(response.status).toBe(302)
    await expect(getOAuthStates()).resolves.toHaveLength(1)
    expect(error).toHaveBeenCalledWith({
      event: 'rate_limit_error',
      route: '/login',
      scope: 'ip',
      cfRay: 'login-ray',
      clientId: null,
      errorName: 'Error',
    })
  })

  it.each([
    ['missing client ID', { redirect_uri: REDIRECT_URI }],
    ['missing redirect URI', { client_id: CLIENT_ID }],
    ['unknown client', { client_id: 'unknown', redirect_uri: REDIRECT_URI }],
    [
      'unregistered redirect URI',
      {
        client_id: CLIENT_ID,
        redirect_uri: 'https://client.example/other',
      },
    ],
    [
      'redirect URI with an added path',
      {
        client_id: CLIENT_ID,
        redirect_uri: `${REDIRECT_URI}/extra`,
      },
    ],
    [
      'redirect URI with a deceptive host',
      {
        client_id: CLIENT_ID,
        redirect_uri: 'https://client.example.evil.test/callback',
      },
    ],
  ])('rejects %s without storing a state', async (_caseName, query) => {
    const response = await requestLogin(query)

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({
      error: 'invalid_request',
    })
    await expect(getOAuthStates()).resolves.toHaveLength(0)
  })

  it('rejects a disabled client without storing a state', async () => {
    await env.DB.prepare('DELETE FROM clients WHERE client_id = ?')
      .bind(CLIENT_ID)
      .run()
    await insertClient({ disabled: true })

    const response = await requestLogin()

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({
      error: 'invalid_request',
    })
    await expect(getOAuthStates()).resolves.toHaveLength(0)
  })
})
