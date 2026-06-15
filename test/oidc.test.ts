import { env } from 'cloudflare:workers'
import { beforeEach, describe, expect, it } from 'vitest'

import type { AppBindings } from '../src/lib/config'
import { hashAuthToken, hashClientSecret } from '../src/lib/crypto'
import { app } from '../src/index'
import { allowingRateLimiter } from './rate-limit'

const NOW = 1_700_000_000
const CLIENT_ID = 'client-a'
const CLIENT_SECRET = 'client-secret'
const REDIRECT_URI = 'https://client.example/callback'
const SESSION_SECRET = 's'.repeat(32)
const OIDC_PRIVATE_JWK = '{"key_ops":["sign"],"ext":true,"kty":"EC","x":"ODz8oKiIPaLIpdF2pMEKF3u0gc81OfilEdDaI7bP-K4","y":"0BIjbLOo0At-sq8ah16FdYhzuP8kQYbnt4PKfD9Trvw","crv":"P-256","d":"dM4taUd_F9VZHVziH6vmKIRlGgFtkbcQ11IFr_5LdHA","kid":"test-key","alg":"ES256"}'
const VALID_PKCE_CHALLENGE = 'a'.repeat(43)

function bindings(): AppBindings {
  return {
    DB: env.DB,
    PUBLIC_RATE_LIMITER: allowingRateLimiter,
    CLIENT_RATE_LIMITER: allowingRateLimiter,
    GITHUB_CLIENT_ID: 'github-client-id',
    GITHUB_CLIENT_SECRET: 'github-client-secret',
    GITHUB_ORG: 'example-org',
    GITHUB_CALLBACK_URL: 'https://auth.example.com/callback',
    GOOGLE_CLIENT_ID: 'google-client-id',
    GOOGLE_CLIENT_SECRET: 'google-client-secret',
    GOOGLE_CALLBACK_URL: 'https://auth.example.com/callback',
    GOOGLE_ALLOWED_HD: 'example.com',
    SESSION_SECRET,
    OIDC_ISSUER: 'https://auth.example.com',
    OIDC_PRIVATE_JWK,
  }
}

function basic(): string {
  return `Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`
}

function denyingRateLimiter(calls: unknown[] = []): RateLimit {
  return {
    async limit(request) {
      calls.push(request)
      return { success: false }
    },
  }
}

beforeEach(async () => {
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO clients (client_id, client_secret_hash, created_at) VALUES (?, ?, ?)`).bind(CLIENT_ID, await hashClientSecret(CLIENT_SECRET), NOW),
    env.DB.prepare(`INSERT INTO allowed_redirect_uris (client_id, redirect_uri, created_at) VALUES (?, ?, ?)`).bind(CLIENT_ID, REDIRECT_URI, NOW),
  ])
})

describe('OIDC provider endpoints', () => {
  it('publishes discovery and JWKS documents', async () => {
    const discovery = await app.request('https://auth.example.com/.well-known/openid-configuration', {}, bindings())
    expect(discovery.status).toBe(200)
    await expect(discovery.json()).resolves.toMatchObject({
      issuer: 'https://auth.example.com',
      authorization_endpoint: 'https://auth.example.com/authorize',
      token_endpoint: 'https://auth.example.com/token',
      jwks_uri: 'https://auth.example.com/jwks.json',
      id_token_signing_alg_values_supported: ['ES256'],
    })

    const jwks = await app.request('https://auth.example.com/jwks.json', {}, bindings())
    expect(jwks.status).toBe(200)
    await expect(jwks.json()).resolves.toMatchObject({ keys: [{ kid: 'test-key', kty: 'EC', alg: 'ES256' }] })
  })

  it('starts GitHub authorization and stores OIDC request state', async () => {
    const url = new URL('https://auth.example.com/authorize')
    url.search = new URLSearchParams({
      response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
      scope: 'openid', state: 'client-state', nonce: 'nonce-value', provider: 'github',
      code_challenge: VALID_PKCE_CHALLENGE, code_challenge_method: 'S256',
    }).toString()
    const response = await app.request(url, {}, bindings())
    expect(response.status).toBe(302)
    const location = new URL(response.headers.get('location') ?? '')
    expect(location.origin + location.pathname).toBe('https://github.com/login/oauth/authorize')

    const row = await env.DB.prepare(`SELECT client_state, nonce, provider, code_challenge_method FROM oauth_states`).first<{ client_state: string; nonce: string; provider: string; code_challenge_method: string }>()
    expect(row).toEqual({ client_state: 'client-state', nonce: 'nonce-value', provider: 'github', code_challenge_method: 'S256' })
  })

  it('starts Google authorization with OIDC parameters and hd hint', async () => {
    const url = new URL('https://auth.example.com/authorize')
    url.search = new URLSearchParams({ response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, scope: 'openid', state: 's', nonce: 'n', provider: 'google' }).toString()
    const response = await app.request(url, {}, bindings())
    expect(response.status).toBe(302)
    const location = new URL(response.headers.get('location') ?? '')
    expect(location.origin + location.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth')
    expect(location.searchParams.get('response_type')).toBe('code')
    expect(location.searchParams.get('client_id')).toBe('google-client-id')
    expect(location.searchParams.get('redirect_uri')).toBe('https://auth.example.com/callback')
    expect(location.searchParams.get('scope')).toBe('openid email profile')
    expect(location.searchParams.get('nonce')).toBe('n')
    expect(location.searchParams.get('hd')).toBe('example.com')
    expect(location.searchParams.get('state')).toMatch(/^[A-Za-z0-9_-]{43}$/)
    const row = await env.DB.prepare(`SELECT client_state, nonce, provider FROM oauth_states`).first<{ client_state: string; nonce: string; provider: string }>()
    expect(row).toEqual({ client_state: 's', nonce: 'n', provider: 'google' })
  })

  it.each([
    ['method without challenge', { code_challenge_method: 'S256' }],
    ['unsupported plain method', { code_challenge: VALID_PKCE_CHALLENGE, code_challenge_method: 'plain' }],
    ['malformed S256 challenge', { code_challenge: 'short', code_challenge_method: 'S256' }],
  ])('rejects malformed PKCE authorize requests: %s', async (_caseName, pkce) => {
    const url = new URL('https://auth.example.com/authorize')
    url.search = new URLSearchParams({
      response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
      scope: 'openid', state: 'client-state', nonce: 'nonce-value', provider: 'github',
      ...pkce,
    }).toString()

    const response = await app.request(url, {}, bindings())

    expect(response.status).toBe(302)
    const location = new URL(response.headers.get('location') ?? '')
    expect(location.searchParams.get('error')).toBe('invalid_request')
    expect((await env.DB.prepare(`SELECT COUNT(*) AS count FROM oauth_states`).first<{ count: number }>())?.count).toBe(0)
  })

  it('applies IP rate limiting to /token before client authentication', async () => {
    const publicCalls: unknown[] = []
    const response = await app.request('https://auth.example.com/token', {
      method: 'POST',
      headers: { 'CF-Connecting-IP': '203.0.113.42' },
    }, { ...bindings(), PUBLIC_RATE_LIMITER: denyingRateLimiter(publicCalls) })

    expect(response.status).toBe(429)
    await expect(response.json()).resolves.toEqual({ error: 'rate_limited' })
    expect(publicCalls).toEqual([{ key: 'token:ip:203.0.113.42' }])
  })

  it('applies client rate limiting to /token after successful client authentication', async () => {
    const clientCalls: unknown[] = []
    const response = await app.request('https://auth.example.com/token', {
      method: 'POST',
      headers: { Authorization: basic(), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'missing', redirect_uri: REDIRECT_URI }),
    }, { ...bindings(), CLIENT_RATE_LIMITER: denyingRateLimiter(clientCalls) })

    expect(response.status).toBe(429)
    await expect(response.json()).resolves.toEqual({ error: 'rate_limited' })
    expect(clientCalls).toEqual([{ key: `token:client:${CLIENT_ID}` }])
  })

  it('does not apply client rate limiting before successful client authentication', async () => {
    const clientCalls: unknown[] = []
    const response = await app.request('https://auth.example.com/token', {
      method: 'POST',
      headers: { Authorization: `Basic ${btoa(`${CLIENT_ID}:wrong`)}` },
    }, { ...bindings(), CLIENT_RATE_LIMITER: denyingRateLimiter(clientCalls) })

    expect(response.status).toBe(401)
    expect(clientCalls).toEqual([])
  })

  it('exchanges an authorization code for bearer and signed ID tokens', async () => {
    await env.DB.prepare(`INSERT INTO users (user_id, created_at, updated_at) VALUES (?, ?, ?)`).bind('user-123', NOW, NOW).run()
    const codeHash = await hashAuthToken('code-value', SESSION_SECRET, 'auth-code')
    await env.DB.prepare(
      `INSERT INTO auth_codes (code_hash, user_id, client_id, redirect_uri, scope, nonce, provider, auth_time, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(codeHash, 'user-123', CLIENT_ID, REDIRECT_URI, 'openid', 'nonce-value', 'github', NOW, NOW, Math.floor(Date.now() / 1000) + 60).run()

    const response = await app.request('https://auth.example.com/token', {
      method: 'POST',
      headers: { Authorization: basic(), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'code-value', redirect_uri: REDIRECT_URI }),
    }, bindings())
    expect(response.status).toBe(200)
    const body = await response.json() as { access_token: string; id_token: string; token_type: string }
    expect(body.token_type).toBe('Bearer')
    expect(body.id_token.split('.')).toHaveLength(3)
    const claims = JSON.parse(atob(body.id_token.split('.')[1].replaceAll('-', '+').replaceAll('_', '/')))
    expect(claims).toMatchObject({ iss: 'https://auth.example.com', sub: 'user-123', aud: CLIENT_ID, nonce: 'nonce-value' })

    const userinfo = await app.request('https://auth.example.com/userinfo', { headers: { Authorization: `Bearer ${body.access_token}` } }, bindings())
    expect(userinfo.status).toBe(200)
    expect(userinfo.headers.get('cache-control')).toBe('no-store')
    await expect(userinfo.json()).resolves.toEqual({ sub: 'user-123' })
  })

  it('exchanges a Google-backed authorization code with internal user_id as subject', async () => {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO members (member_id, display_name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`).bind('member-1', 'Member One', 'active', NOW, NOW),
      env.DB.prepare(`INSERT INTO member_emails (normalized_email, member_id, login_allowed, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`).bind('member@example.com', 'member-1', 1, NOW, NOW),
      env.DB.prepare(`INSERT INTO users (user_id, member_id, created_at, updated_at) VALUES (?, ?, ?, ?)`).bind('internal-user-123', 'member-1', NOW, NOW),
      env.DB.prepare(`INSERT INTO external_identities (provider, provider_user_id, user_id, provider_login, email, email_verified, hosted_domain, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind('google', 'google-sub-123', 'internal-user-123', 'Member One', 'member@example.com', 1, 'example.com', NOW, NOW),
    ])
    const codeHash = await hashAuthToken('google-code-value', SESSION_SECRET, 'auth-code')
    await env.DB.prepare(
      `INSERT INTO auth_codes (code_hash, user_id, client_id, redirect_uri, scope, nonce, provider, provider_user_id, auth_time, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(codeHash, 'internal-user-123', CLIENT_ID, REDIRECT_URI, 'openid', 'nonce-value', 'google', 'google-sub-123', NOW, NOW, Math.floor(Date.now() / 1000) + 60).run()

    const response = await app.request('https://auth.example.com/token', {
      method: 'POST',
      headers: { Authorization: basic(), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'google-code-value', redirect_uri: REDIRECT_URI }),
    }, bindings())

    expect(response.status).toBe(200)
    const body = await response.json() as { id_token: string }
    const claims = JSON.parse(atob(body.id_token.split('.')[1].replaceAll('-', '+').replaceAll('_', '/')))
    expect(claims.sub).toBe('internal-user-123')
    expect(claims.sub).not.toBe('google-sub-123')
  })

  it('rejects /token when the linked member email is not allowed to log in', async () => {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO members (member_id, display_name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`).bind('member-1', 'Member One', 'active', NOW, NOW),
      env.DB.prepare(`INSERT INTO member_emails (normalized_email, member_id, login_allowed, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`).bind('member@example.com', 'member-1', 0, NOW, NOW),
      env.DB.prepare(`INSERT INTO users (user_id, member_id, created_at, updated_at) VALUES (?, ?, ?, ?)`).bind('user-123', 'member-1', NOW, NOW),
      env.DB.prepare(`INSERT INTO external_identities (provider, provider_user_id, user_id, provider_login, email, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind('github', 'gh-123', 'user-123', 'member', 'member@example.com', 1, NOW, NOW),
    ])
    const codeHash = await hashAuthToken('code-value', SESSION_SECRET, 'auth-code')
    await env.DB.prepare(
      `INSERT INTO auth_codes (code_hash, user_id, client_id, redirect_uri, scope, nonce, provider, auth_time, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(codeHash, 'user-123', CLIENT_ID, REDIRECT_URI, 'openid', 'nonce-value', 'github', NOW, NOW, Math.floor(Date.now() / 1000) + 60).run()

    const response = await app.request('https://auth.example.com/token', {
      method: 'POST',
      headers: { Authorization: basic(), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'code-value', redirect_uri: REDIRECT_URI }),
    }, bindings())

    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toEqual({ error: 'access_denied' })
    expect((await env.DB.prepare(`SELECT COUNT(*) AS count FROM access_tokens`).first<{ count: number }>())?.count).toBe(0)
  })

  it('rejects /userinfo when the linked member email is not allowed to log in', async () => {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO members (member_id, display_name, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`).bind('member-1', 'Member One', 'active', NOW, NOW),
      env.DB.prepare(`INSERT INTO member_emails (normalized_email, member_id, login_allowed, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`).bind('member@example.com', 'member-1', 0, NOW, NOW),
      env.DB.prepare(`INSERT INTO users (user_id, member_id, created_at, updated_at) VALUES (?, ?, ?, ?)`).bind('user-123', 'member-1', NOW, NOW),
      env.DB.prepare(`INSERT INTO external_identities (provider, provider_user_id, user_id, provider_login, email, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind('github', 'gh-123', 'user-123', 'member', 'member@example.com', 1, NOW, NOW),
    ])
    const tokenHash = await hashAuthToken('access-token-value', SESSION_SECRET, 'access-token')
    await env.DB.prepare(
      `INSERT INTO access_tokens (token_hash, user_id, client_id, scope, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(tokenHash, 'user-123', CLIENT_ID, 'openid', NOW, Math.floor(Date.now() / 1000) + 60).run()

    const response = await app.request('https://auth.example.com/userinfo', {
      headers: { Authorization: 'Bearer access-token-value' },
    }, bindings())

    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toBe('Bearer realm="userinfo"')
    await expect(response.json()).resolves.toEqual({ error: 'invalid_token' })
  })

  it('rejects migrated authorization codes with null OIDC fields', async () => {
    await env.DB.prepare(`INSERT INTO users (user_id, created_at, updated_at) VALUES (?, ?, ?)`).bind('user-123', NOW, NOW).run()
    const codeHash = await hashAuthToken('legacy-code', SESSION_SECRET, 'auth-code')
    await env.DB.prepare(
      `INSERT INTO auth_codes (code_hash, user_id, client_id, redirect_uri, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(codeHash, 'user-123', CLIENT_ID, REDIRECT_URI, NOW, Math.floor(Date.now() / 1000) + 60).run()

    const response = await app.request('https://auth.example.com/token', {
      method: 'POST',
      headers: { Authorization: basic(), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: 'legacy-code', redirect_uri: REDIRECT_URI }),
    }, bindings())

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({ error: 'invalid_grant' })
    expect((await env.DB.prepare(`SELECT COUNT(*) AS count FROM access_tokens`).first<{ count: number }>())?.count).toBe(0)
  })

  it('uses a Bearer challenge for /userinfo authentication failures', async () => {
    const response = await app.request('https://auth.example.com/userinfo', {}, bindings())

    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toBe('Bearer realm="userinfo"')
  })
})
