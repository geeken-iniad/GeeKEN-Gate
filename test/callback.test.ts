import { env } from 'cloudflare:workers'
import { Hono } from 'hono'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { AppBindings } from '../src/lib/config'
import { hashAuthToken, hashClientSecret } from '../src/lib/crypto'
import { GitHubAuthError } from '../src/lib/github'
import { GoogleAuthError } from '../src/lib/google'
import { createCallbackHandler } from '../src/routes/callback'
import { handleToken, handleUserinfo } from '../src/routes/oidc'
import { allowingRateLimiter } from './rate-limit'

const NOW = 1_700_000_000
const CLIENT_ID = 'client-a'
const CLIENT_SECRET = 'client-secret'
const REDIRECT_URI = 'https://client.example/callback?source=login'
const SESSION_SECRET = 's'.repeat(32)
const OIDC_PRIVATE_JWK = '{"key_ops":["sign"],"ext":true,"kty":"EC","x":"ODz8oKiIPaLIpdF2pMEKF3u0gc81OfilEdDaI7bP-K4","y":"0BIjbLOo0At-sq8ah16FdYhzuP8kQYbnt4PKfD9Trvw","crv":"P-256","d":"dM4taUd_F9VZHVziH6vmKIRlGgFtkbcQ11IFr_5LdHA","kid":"test-key","alg":"ES256"}'
const OAUTH_STATE = 'oauth-state-value'
const GITHUB_CODE = 'github-code'
const EXISTING_USER_ID = 'user-123'
const GITHUB_USER = {
  githubId: '123456',
  githubLogin: 'octocat',
}
const GOOGLE_USER = {
  googleSub: 'google-sub-123',
  email: 'member@example.com',
  hostedDomain: 'example.com',
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
    GOOGLE_CLIENT_ID: 'google-client-id',
    GOOGLE_CLIENT_SECRET: 'google-client-secret',
    GOOGLE_CALLBACK_URL: 'https://auth.example.com/callback',
    GOOGLE_ALLOWED_HD: 'example.com',
    SESSION_SECRET,
    OIDC_ISSUER: 'https://auth.example.com',
    OIDC_PRIVATE_JWK,
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
         (state_hash, client_id, redirect_uri, client_state, scope, nonce, provider, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(stateHash, CLIENT_ID, REDIRECT_URI, 'client-state', 'openid', 'nonce-value', 'github', NOW, expiresAt),
  ])
}

function createTestApp(authenticate = vi.fn().mockResolvedValue(GITHUB_USER)) {
  const app = new Hono<{ Bindings: AppBindings }>()
  app.get('/callback', createCallbackHandler(authenticate))

  return { app, authenticate }
}

function createGoogleTestApp(authenticateGoogle = vi.fn().mockResolvedValue(GOOGLE_USER)) {
  const app = new Hono<{ Bindings: AppBindings }>()
  app.get('/callback', createCallbackHandler(vi.fn(), authenticateGoogle))

  return { app, authenticateGoogle }
}

function createGoogleOidcTestApp(authenticateGoogle = vi.fn().mockResolvedValue(GOOGLE_USER)) {
  const app = new Hono<{ Bindings: AppBindings }>()
  app.get('/callback', createCallbackHandler(vi.fn(), authenticateGoogle))
  app.post('/token', handleToken)
  app.get('/userinfo', handleUserinfo)

  return { app, authenticateGoogle }
}

function basic(): string {
  return `Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`
}

async function useGoogleState(): Promise<void> {
  await env.DB.prepare(`UPDATE oauth_states SET provider = 'google'`).run()
}

async function insertMember(
  email = GOOGLE_USER.email,
  memberId = 'member-a',
  status: 'active' | 'suspended' | 'left' = 'active',
  loginAllowed: 0 | 1 = 1,
) {
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO members (member_id, display_name, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).bind(memberId, 'Member A', status, NOW, NOW),
    env.DB.prepare(
      `INSERT INTO member_emails (normalized_email, member_id, login_allowed, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).bind(email, memberId, loginAllowed, NOW, NOW),
  ])
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
      `SELECT users.user_id, users.created_at, users.updated_at,
              external_identities.provider_user_id AS github_id,
              external_identities.provider_login AS github_login
       FROM users
       INNER JOIN external_identities
         ON external_identities.user_id = users.user_id
        AND external_identities.provider = 'github'`,
    ).first<{
      user_id: string
      github_id: string
      github_login: string
      created_at: number
      updated_at: number
    }>()
    expect(user).toMatchObject({
      github_id: GITHUB_USER.githubId,
      github_login: GITHUB_USER.githubLogin,
    })
    expect(user?.user_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    )
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
         (user_id, created_at, updated_at)
       VALUES (?, ?, ?)`,
    )
      .bind(EXISTING_USER_ID, NOW, NOW)
      .run()
    await env.DB.prepare(
      `INSERT INTO external_identities
         (provider, provider_user_id, user_id, provider_login, created_at, updated_at)
       VALUES ('github', ?, ?, ?, ?, ?)`,
    )
      .bind(GITHUB_USER.githubId, EXISTING_USER_ID, 'old-login', NOW, NOW)
      .run()
    const { app } = createTestApp()

    const response = await requestCallback(app)

    expect(response.status).toBe(302)
    const user = await env.DB.prepare(
      `SELECT users.created_at, users.updated_at,
              external_identities.provider_login AS github_login
       FROM users
       INNER JOIN external_identities
         ON external_identities.user_id = users.user_id
        AND external_identities.provider = 'github'
       WHERE users.user_id = ?`,
    )
      .bind(EXISTING_USER_ID)
      .first<{
        github_login: string
        created_at: number
        updated_at: number
      }>()
    expect(user?.github_login).toBe(GITHUB_USER.githubLogin)
    expect(user?.created_at).toBe(NOW)
    expect(user?.updated_at).toBeGreaterThan(NOW)
  })

  it('admits an active member through Google and stores internal user identity', async () => {
    await useGoogleState()
    await insertMember()
    const { app, authenticateGoogle } = createGoogleTestApp()

    const response = await requestCallback(app, { code: 'google-code', state: OAUTH_STATE })

    expect(response.status).toBe(302)
    expect(authenticateGoogle).toHaveBeenCalledWith('google-code', {
      clientId: 'google-client-id',
      clientSecret: 'google-client-secret',
      callbackUrl: new URL('https://auth.example.com/callback'),
      allowedHostedDomains: ['example.com'],
      nonce: 'nonce-value',
    })
    const identity = await env.DB.prepare(
      `SELECT users.user_id, users.member_id, external_identities.provider_user_id,
              external_identities.email, external_identities.email_verified,
              external_identities.hosted_domain
       FROM users
       INNER JOIN external_identities ON external_identities.user_id = users.user_id
       WHERE external_identities.provider = 'google'`,
    ).first<{ user_id: string; member_id: string; provider_user_id: string; email: string; email_verified: number; hosted_domain: string }>()
    expect(identity).toMatchObject({
      member_id: 'member-a',
      provider_user_id: GOOGLE_USER.googleSub,
      email: GOOGLE_USER.email,
      email_verified: 1,
      hosted_domain: GOOGLE_USER.hostedDomain,
    })
    expect(identity?.user_id).not.toBe(GOOGLE_USER.googleSub)
    expect(await countRows('sessions')).toBe(1)
    expect(await countRows('auth_codes')).toBe(1)
  })

  it('rejects a same-domain Google user who is not a member', async () => {
    await useGoogleState()
    const { app } = createGoogleTestApp()

    const response = await requestCallback(app, { code: 'google-code', state: OAUTH_STATE })

    expect(response.status).toBe(302)
    expect(new URL(response.headers.get('location') ?? '').searchParams.get('error')).toBe('access_denied')
    expect(await countRows('users')).toBe(0)
    expect(await countRows('external_identities')).toBe(0)
    expect(await countRows('sessions')).toBe(0)
    await expect(getAuthEvents()).resolves.toEqual([
      expect.objectContaining({ success: 0, reason: 'member_email_not_found' }),
    ])
  })

  it.each([
    ['suspended member', 'suspended', 1, 'member_suspended'],
    ['left member', 'left', 1, 'member_left'],
    ['login disabled member email', 'active', 0, 'member_login_disabled'],
  ] as const)('rejects a Google login for %s', async (_caseName, status, loginAllowed, reason) => {
    await useGoogleState()
    await insertMember(GOOGLE_USER.email, 'member-a', status, loginAllowed)
    const { app } = createGoogleTestApp()

    const response = await requestCallback(app, { code: 'google-code', state: OAUTH_STATE })

    expect(response.status).toBe(302)
    expect(await countRows('sessions')).toBe(0)
    expect(await countRows('auth_codes')).toBe(0)
    expect(await countRows('external_identities')).toBe(0)
    await expect(getAuthEvents()).resolves.toEqual([
      expect.objectContaining({ success: 0, reason }),
    ])
  })

  it('rejects a Google login when the existing member user is disabled', async () => {
    await useGoogleState()
    await insertMember()
    await env.DB.prepare(
      `INSERT INTO users (user_id, member_id, disabled_at, created_at, updated_at)
       VALUES (?, 'member-a', ?, ?, ?)`,
    ).bind(EXISTING_USER_ID, NOW, NOW, NOW).run()
    const { app } = createGoogleTestApp()

    const response = await requestCallback(app, { code: 'google-code', state: OAUTH_STATE })

    expect(response.status).toBe(302)
    expect(await countRows('external_identities')).toBe(0)
    await expect(getAuthEvents()).resolves.toEqual([
      expect.objectContaining({ success: 0, reason: 'user_disabled' }),
    ])
  })

  it.each([
    ['unverified email', 'google_email_not_verified'],
    ['missing hd', 'google_hd_missing'],
    ['non-allowed hd', 'google_hd_not_allowed'],
  ] as const)('redirects Google ID token rejection for %s', async (_caseName, reason) => {
    await useGoogleState()
    const { app } = createGoogleTestApp(vi.fn().mockRejectedValue(new GoogleAuthError(reason)))

    const response = await requestCallback(app, { code: 'google-code', state: OAUTH_STATE })

    expect(response.status).toBe(302)
    expect(await countRows('users')).toBe(0)
    expect(await countRows('external_identities')).toBe(0)
    await expect(getAuthEvents()).resolves.toEqual([
      expect.objectContaining({ success: 0, reason }),
    ])
  })

  it('reuses an existing Google identity', async () => {
    await useGoogleState()
    await insertMember()
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO users (user_id, member_id, created_at, updated_at) VALUES (?, 'member-a', ?, ?)`).bind(EXISTING_USER_ID, NOW, NOW),
      env.DB.prepare(`INSERT INTO external_identities (provider, provider_user_id, user_id, email, email_verified, hosted_domain, created_at, updated_at) VALUES ('google', ?, ?, ?, 1, ?, ?, ?)`).bind(GOOGLE_USER.googleSub, EXISTING_USER_ID, 'old@example.com', 'example.com', NOW, NOW),
    ])
    const { app } = createGoogleTestApp()

    const response = await requestCallback(app, { code: 'google-code', state: OAUTH_STATE })

    expect(response.status).toBe(302)
    expect(await countRows('users')).toBe(1)
    const identity = await env.DB.prepare(`SELECT user_id, email FROM external_identities WHERE provider = 'google'`).first<{ user_id: string; email: string }>()
    expect(identity).toEqual({ user_id: EXISTING_USER_ID, email: GOOGLE_USER.email })
  })

  it('links Google identity to an existing member user', async () => {
    await useGoogleState()
    await insertMember()
    await env.DB.prepare(`INSERT INTO users (user_id, member_id, created_at, updated_at) VALUES (?, 'member-a', ?, ?)`).bind(EXISTING_USER_ID, NOW, NOW).run()
    const { app } = createGoogleTestApp()

    const response = await requestCallback(app, { code: 'google-code', state: OAUTH_STATE })

    expect(response.status).toBe(302)
    expect(await countRows('users')).toBe(1)
    const identity = await env.DB.prepare(`SELECT user_id FROM external_identities WHERE provider = 'google'`).first<{ user_id: string }>()
    expect(identity?.user_id).toBe(EXISTING_USER_ID)
  })

  it('admits Google login with current allowed email despite another disallowed linked email', async () => {
    await useGoogleState()
    await insertMember()
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO member_emails (normalized_email, member_id, login_allowed, created_at, updated_at)
         VALUES (?, 'member-a', 0, ?, ?)`,
      ).bind('stale@example.com', NOW, NOW),
      env.DB.prepare(`INSERT INTO users (user_id, member_id, created_at, updated_at) VALUES (?, 'member-a', ?, ?)`).bind(EXISTING_USER_ID, NOW, NOW),
      env.DB.prepare(
        `INSERT INTO external_identities
           (provider, provider_user_id, user_id, provider_login, email, email_verified, created_at, updated_at)
         VALUES ('github', 'stale-gh', ?, 'stale', 'stale@example.com', 1, ?, ?)`,
      ).bind(EXISTING_USER_ID, NOW, NOW),
    ])
    const { app } = createGoogleTestApp()

    const response = await requestCallback(app, { code: 'google-code', state: OAUTH_STATE })

    expect(response.status).toBe(302)
    expect(new URL(response.headers.get('location') ?? '').searchParams.get('error')).toBeNull()
    expect(await countRows('sessions')).toBe(1)
    const googleIdentity = await env.DB.prepare(
      `SELECT user_id, email FROM external_identities WHERE provider = 'google'`,
    ).first<{ user_id: string; email: string }>()
    expect(googleIdentity).toEqual({ user_id: EXISTING_USER_ID, email: GOOGLE_USER.email })
  })

  it('exchanges and uses Google OIDC artifacts despite another disallowed linked email', async () => {
    await useGoogleState()
    await env.DB.prepare(
      `UPDATE clients SET client_secret_hash = ? WHERE client_id = ?`,
    ).bind(await hashClientSecret(CLIENT_SECRET), CLIENT_ID).run()
    await insertMember()
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO member_emails (normalized_email, member_id, login_allowed, created_at, updated_at)
         VALUES (?, 'member-a', 0, ?, ?)`,
      ).bind('stale@example.com', NOW, NOW),
      env.DB.prepare(`INSERT INTO users (user_id, member_id, created_at, updated_at) VALUES (?, 'member-a', ?, ?)`).bind(EXISTING_USER_ID, NOW, NOW),
      env.DB.prepare(
        `INSERT INTO external_identities
           (provider, provider_user_id, user_id, provider_login, email, email_verified, created_at, updated_at)
         VALUES ('github', 'stale-gh', ?, 'stale', 'stale@example.com', 1, ?, ?)`,
      ).bind(EXISTING_USER_ID, NOW, NOW),
    ])
    const { app } = createGoogleOidcTestApp()

    const callbackResponse = await requestCallback(app, { code: 'google-code', state: OAUTH_STATE })

    expect(callbackResponse.status).toBe(302)
    const authCode = new URL(callbackResponse.headers.get('location') ?? '').searchParams.get('code')
    expect(authCode).toMatch(/^[A-Za-z0-9_-]{43}$/)

    const tokenResponse = await app.request('https://auth.example.com/token', {
      method: 'POST',
      headers: { Authorization: basic(), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: authCode ?? '', redirect_uri: REDIRECT_URI }),
    }, createBindings())

    expect(tokenResponse.status).toBe(200)
    const tokenBody = await tokenResponse.json() as { access_token: string; id_token: string }
    const claims = JSON.parse(atob(tokenBody.id_token.split('.')[1].replaceAll('-', '+').replaceAll('_', '/')))
    expect(claims.sub).toBe(EXISTING_USER_ID)
    expect(claims.sub).not.toBe(GOOGLE_USER.googleSub)

    const userinfoResponse = await app.request('https://auth.example.com/userinfo', {
      headers: { Authorization: `Bearer ${tokenBody.access_token}` },
    }, createBindings())
    expect(userinfoResponse.status).toBe(200)
    await expect(userinfoResponse.json()).resolves.toEqual({ sub: EXISTING_USER_ID })
  })

  it('rechecks the Google identity email before exchanging Google OIDC artifacts', async () => {
    await useGoogleState()
    await env.DB.prepare(
      `UPDATE clients SET client_secret_hash = ? WHERE client_id = ?`,
    ).bind(await hashClientSecret(CLIENT_SECRET), CLIENT_ID).run()
    await insertMember()
    const { app } = createGoogleOidcTestApp()

    const callbackResponse = await requestCallback(app, { code: 'google-code', state: OAUTH_STATE })
    expect(callbackResponse.status).toBe(302)
    const authCode = new URL(callbackResponse.headers.get('location') ?? '').searchParams.get('code')
    await env.DB.prepare(
      `UPDATE member_emails SET login_allowed = 0 WHERE normalized_email = ?`,
    ).bind(GOOGLE_USER.email).run()

    const tokenResponse = await app.request('https://auth.example.com/token', {
      method: 'POST',
      headers: { Authorization: basic(), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code: authCode ?? '', redirect_uri: REDIRECT_URI }),
    }, createBindings())

    expect(tokenResponse.status).toBe(403)
    await expect(tokenResponse.json()).resolves.toEqual({ error: 'access_denied' })
  })

  it('does not persist a Google identity when the current email is rejected for an existing member user', async () => {
    await useGoogleState()
    await insertMember(GOOGLE_USER.email, 'member-a', 'active', 0)
    await env.DB.prepare(`INSERT INTO users (user_id, member_id, created_at, updated_at) VALUES (?, 'member-a', ?, ?)`).bind(EXISTING_USER_ID, NOW, NOW).run()
    const { app } = createGoogleTestApp()

    const response = await requestCallback(app, { code: 'google-code', state: OAUTH_STATE })

    expect(response.status).toBe(302)
    expect(await countRows('sessions')).toBe(0)
    expect(await env.DB.prepare(`SELECT COUNT(*) AS count FROM external_identities WHERE provider = 'google'`).first<{ count: number }>()).toEqual({ count: 0 })
    await expect(getAuthEvents()).resolves.toEqual([
      expect.objectContaining({ success: 0, reason: 'member_login_disabled' }),
    ])
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

  it('rejects migrated states with missing OIDC fields before calling GitHub', async () => {
    await env.DB.prepare(`UPDATE oauth_states SET scope = NULL, nonce = NULL, provider = NULL`).run()
    const { app, authenticate } = createTestApp()

    const response = await requestCallback(app)

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({ error: 'invalid_request' })
    expect(authenticate).not.toHaveBeenCalled()
    expect(await countRows('sessions')).toBe(0)
    expect(await countRows('auth_codes')).toBe(0)
    await expect(getAuthEvents()).resolves.toEqual([
      expect.objectContaining({ success: 0, reason: 'invalid_oidc_state' }),
    ])
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

  it('rejects a disabled user without creating credentials', async () => {
    await env.DB.prepare(
      `INSERT INTO users (user_id, disabled_at, created_at, updated_at)
       VALUES (?, ?, ?, ?)`,
    )
      .bind(EXISTING_USER_ID, NOW, NOW, NOW)
      .run()
    await env.DB.prepare(
      `INSERT INTO external_identities
         (provider, provider_user_id, user_id, provider_login, created_at, updated_at)
       VALUES ('github', ?, ?, ?, ?, ?)`,
    )
      .bind(GITHUB_USER.githubId, EXISTING_USER_ID, GITHUB_USER.githubLogin, NOW, NOW)
      .run()
    const { app } = createTestApp()

    const response = await requestCallback(app)

    expect(response.status).toBe(302)
    expect(
      new URL(response.headers.get('location') ?? '').searchParams.get('error'),
    ).toBe('access_denied')
    expect(await countRows('users')).toBe(1)
    expect(await countRows('sessions')).toBe(0)
    expect(await countRows('auth_codes')).toBe(0)
    await expect(getAuthEvents()).resolves.toEqual([
      expect.objectContaining({
        github_id: GITHUB_USER.githubId,
        github_login: GITHUB_USER.githubLogin,
        success: 0,
        reason: 'disabled_user',
      }),
    ])
  })

  it('rejects a suspended member without creating credentials', async () => {
    await env.DB.prepare(
      `INSERT INTO members (member_id, display_name, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
      .bind('member-a', 'Octo Cat', 'suspended', NOW, NOW)
      .run()
    await env.DB.prepare(
      `INSERT INTO users (user_id, member_id, created_at, updated_at)
       VALUES (?, ?, ?, ?)`,
    )
      .bind(EXISTING_USER_ID, 'member-a', NOW, NOW)
      .run()
    await env.DB.prepare(
      `INSERT INTO external_identities
         (provider, provider_user_id, user_id, provider_login, created_at, updated_at)
       VALUES ('github', ?, ?, ?, ?, ?)`,
    )
      .bind(GITHUB_USER.githubId, EXISTING_USER_ID, GITHUB_USER.githubLogin, NOW, NOW)
      .run()
    const { app } = createTestApp()

    const response = await requestCallback(app)

    expect(response.status).toBe(302)
    expect(
      new URL(response.headers.get('location') ?? '').searchParams.get('error'),
    ).toBe('access_denied')
    expect(await countRows('sessions')).toBe(0)
    expect(await countRows('auth_codes')).toBe(0)
    await expect(getAuthEvents()).resolves.toEqual([
      expect.objectContaining({
        github_id: GITHUB_USER.githubId,
        github_login: GITHUB_USER.githubLogin,
        success: 0,
        reason: 'member_not_active',
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
