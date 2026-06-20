import { env } from 'cloudflare:workers'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { generateCodeChallenge, hashAuthToken } from '../src/lib/crypto'
import { app } from '../src/index'
import { allowingRateLimiter } from './rate-limit'
import {
  CLIENT_ID,
  CODE_CHALLENGE,
  CODE_VERIFIER,
  NONCE,
  REDIRECT_URI,
  TOKEN_HASH_SECRET,
  createBindings,
  insertClient,
} from './oidc-helpers'

const CLIENT_STATE = 'client-state-value'

afterEach(() => {
  vi.restoreAllMocks()
})

interface OAuthStateRow {
  upstream_state_hash: string
  client_state: string
  client_id: string
  redirect_uri: string
  nonce: string
  code_challenge: string
  provider: string | null
  created_at: number
  expires_at: number
}

async function getOAuthStates(): Promise<OAuthStateRow[]> {
  const result = await env.DB.prepare(
    `SELECT upstream_state_hash, client_state, client_id, redirect_uri,
            nonce, code_challenge, provider, created_at, expires_at
     FROM oauth_states`,
  ).all<OAuthStateRow>()

  return result.results
}

function buildAuthorizeUrl(
  query: Record<string, string>,
): URL {
  const url = new URL('https://auth.example.com/authorize')

  for (const [name, value] of Object.entries(query)) {
    url.searchParams.set(name, value)
  }

  return url
}

async function requestAuthorize(
  query: Record<string, string | undefined> = {},
  bindingOverrides = {},
  headers: HeadersInit = {},
) {
  const defaultQuery: Record<string, string> = {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid',
    state: CLIENT_STATE,
    nonce: NONCE,
    code_challenge: CODE_CHALLENGE,
    code_challenge_method: 'S256',
  }
  const mergedQuery: Record<string, string> = { ...defaultQuery }

  for (const [name, value] of Object.entries(query)) {
    if (value === undefined) {
      delete mergedQuery[name]
    } else {
      mergedQuery[name] = value
    }
  }

  return app.request(
    buildAuthorizeUrl(mergedQuery),
    { headers },
    createBindings(bindingOverrides),
  )
}

describe('GET /authorize', () => {
  let codeChallenge: string

  beforeEach(async () => {
    await insertClient()
    codeChallenge = await generateCodeChallenge(CODE_VERIFIER)
  })

  it('stores a hashed upstream state and redirects to GitHub', async () => {
    const response = await requestAuthorize({
      code_challenge: codeChallenge,
    })

    expect(response.status).toBe(302)
    expect(response.headers.get('cache-control')).toBe('no-store')

    const location = new URL(response.headers.get('location') ?? '')
    const upstreamState = location.searchParams.get('state')

    expect(location.origin + location.pathname).toBe(
      'https://github.com/login/oauth/authorize',
    )
    expect(location.searchParams.get('client_id')).toBe('github-client-id')
    expect(location.searchParams.get('redirect_uri')).toBe(
      'https://auth.example.com/callback',
    )
    expect(location.searchParams.get('scope')).toBe('read:org')
    expect(upstreamState).toMatch(/^[A-Za-z0-9_-]{43}$/)

    const rows = await getOAuthStates()
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      client_state: CLIENT_STATE,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      nonce: NONCE,
      code_challenge: codeChallenge,
      provider: 'github',
    })
    expect(rows[0].upstream_state_hash).not.toBe(upstreamState)
    await expect(
      hashAuthToken(
        upstreamState ?? '',
        TOKEN_HASH_SECRET,
        'oauth-upstream-state',
      ),
    ).resolves.toBe(rows[0].upstream_state_hash)
  })

  it('defaults a missing provider to github as a temporary Phase 2 behavior', async () => {
    const response = await requestAuthorize({ provider: undefined as unknown as string })

    expect(response.status).toBe(302)
    expect((await getOAuthStates())[0]?.provider).toBe('github')
  })

  it('rejects unsupported providers with a clear temporary error', async () => {
    const response = await requestAuthorize({ provider: 'google' })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toMatchObject({
      error: 'invalid_request',
    })
    await expect(getOAuthStates()).resolves.toHaveLength(0)
  })

  it.each([
    ['missing client_id', { client_id: undefined as unknown as string }],
    ['missing redirect_uri', { redirect_uri: undefined as unknown as string }],
    ['missing response_type', { response_type: undefined as unknown as string }],
    ['missing scope', { scope: undefined as unknown as string }],
    ['missing state', { state: undefined as unknown as string }],
    ['missing nonce', { nonce: undefined as unknown as string }],
    ['missing code_challenge', { code_challenge: undefined as unknown as string }],
    [
      'missing code_challenge_method',
      { code_challenge_method: undefined as unknown as string },
    ],
  ])('rejects %s without storing a state', async (_caseName, overrides) => {
    const response = await requestAuthorize({
      code_challenge: codeChallenge,
      ...overrides,
    })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({ error: 'invalid_request' })
    await expect(getOAuthStates()).resolves.toHaveLength(0)
  })

  it.each([
    ['invalid response_type', { response_type: 'token' }],
    ['invalid scope', { scope: 'profile' }],
    ['invalid PKCE method', { code_challenge_method: 'plain' }],
  ])('rejects %s without storing a state', async (_caseName, overrides) => {
    const response = await requestAuthorize({
      code_challenge: codeChallenge,
      ...overrides,
    })

    expect(response.status).toBe(400)
    await expect(getOAuthStates()).resolves.toHaveLength(0)
  })

  it.each([
    ['unknown client', { client_id: 'unknown' }],
    [
      'unregistered redirect URI',
      { redirect_uri: 'https://client.example/other' },
    ],
  ])('rejects %s without storing a state', async (_caseName, overrides) => {
    const response = await requestAuthorize({
      code_challenge: codeChallenge,
      ...overrides,
    })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({ error: 'invalid_request' })
    await expect(getOAuthStates()).resolves.toHaveLength(0)
  })

  it('rejects a disabled client without storing a state', async () => {
    await env.DB.prepare('DELETE FROM clients WHERE client_id = ?')
      .bind(CLIENT_ID)
      .run()
    await insertClient({ disabled: true })

    const response = await requestAuthorize({ code_challenge: codeChallenge })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({ error: 'invalid_request' })
    await expect(getOAuthStates()).resolves.toHaveLength(0)
  })

  it('rejects a rate-limited IP before storing an OAuth state', async () => {
    const limiter = {
      limit: vi.fn().mockResolvedValue({ success: false }),
    } as RateLimit
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const response = await requestAuthorize(
      { code_challenge: codeChallenge },
      { PUBLIC_RATE_LIMITER: limiter },
      {
        'CF-Connecting-IP': '203.0.113.30',
        'CF-Ray': 'authorize-ray',
      },
    )

    expect(response.status).toBe(429)
    expect(response.headers.get('retry-after')).toBe('60')
    await expect(response.json()).resolves.toEqual({
      error: 'rate_limited',
    })
    expect(limiter.limit).toHaveBeenCalledWith({
      key: 'authorize:ip:203.0.113.30',
    })
    await expect(getOAuthStates()).resolves.toHaveLength(0)
    expect(warn).toHaveBeenCalledWith({
      event: 'rate_limited',
      route: '/authorize',
      scope: 'ip',
      cfRay: 'authorize-ray',
      clientId: null,
    })
  })

  it('continues authorize when the rate limiter throws', async () => {
    const limiter = {
      limit: vi.fn().mockRejectedValue(new Error('limiter unavailable')),
    } as RateLimit
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const response = await requestAuthorize(
      { code_challenge: codeChallenge },
      { PUBLIC_RATE_LIMITER: limiter },
      {
        'CF-Connecting-IP': '203.0.113.30',
        'CF-Ray': 'authorize-ray',
      },
    )

    expect(response.status).toBe(302)
    await expect(getOAuthStates()).resolves.toHaveLength(1)
    expect(error).toHaveBeenCalledWith({
      event: 'rate_limit_error',
      route: '/authorize',
      scope: 'ip',
      cfRay: 'authorize-ray',
      clientId: null,
      errorName: 'Error',
    })
  })
})
