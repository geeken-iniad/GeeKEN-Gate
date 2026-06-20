import { env } from 'cloudflare:workers'
import { Hono } from 'hono'

import { app as gateApp } from '../src/index'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { AppBindings } from '../src/lib/config'
import { hashAuthToken, normalizeEmail } from '../src/lib/crypto'
import { GoogleAuthError } from '../src/lib/google'
import { createGoogleCallbackHandler } from '../src/routes/callback-google'
import { allowingRateLimiter } from './rate-limit'
import {
  CLIENT_ID,
  CLIENT_STATE,
  CODE_CHALLENGE,
  EMAIL_HASH_PEPPER_V1,
  GOOGLE_CALLBACK_URL,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  NONCE,
  NOW,
  REDIRECT_URI,
  TOKEN_HASH_SECRET,
  USER_ID,
  createBindings,
  insertClient,
  insertUser,
} from './oidc-helpers'

const GOOGLE_CODE = 'google-code'
const GOOGLE_ISSUER = 'https://accounts.google.com'
const GOOGLE_SUB = 'google-subject'
const GOOGLE_EMAIL = 'user@example.com'
const GOOGLE_HD = 'example.com'

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
  google_issuer: string | null
  google_sub: string | null
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
      'google',
      NOW,
      expiresAt,
    )
    .run()
}

async function insertAllowlist(
  email = GOOGLE_EMAIL,
  userId = USER_ID,
  options: { disabled?: boolean; pepperVersion?: number } = {},
): Promise<void> {
  const normalizedEmail = normalizeEmail(email)
  const pepper =
    options.pepperVersion === 2
      ? 'pepper-v2-secret-32-bytes-long!'
      : EMAIL_HASH_PEPPER_V1
  const emailHash = await hashAuthToken(
    normalizedEmail,
    pepper,
    'email-allowlist',
  )

  await env.DB.prepare(
    `INSERT INTO google_login_allowlist
       (email_hash, pepper_version, user_id, created_at, disabled_at)
     VALUES (?, ?, ?, ?, ?)`,
  )
    .bind(
      emailHash,
      options.pepperVersion ?? 1,
      userId,
      NOW,
      options.disabled ? NOW + 1 : null,
    )
    .run()
}

function createTestApp(authenticate = vi.fn().mockResolvedValue({
  issuer: GOOGLE_ISSUER,
  sub: GOOGLE_SUB,
  email: GOOGLE_EMAIL,
  hd: GOOGLE_HD,
})) {
  const app = new Hono<{ Bindings: AppBindings }>()
  app.get('/callback/google', createGoogleCallbackHandler(authenticate))

  return { app, authenticate }
}

async function requestCallback(
  app: Hono<{ Bindings: AppBindings }>,
  query: Record<string, string> = {
    code: GOOGLE_CODE,
    state: UPSTREAM_STATE,
  },
  bindingOverrides = {},
) {
  const url = new URL('https://auth.example.com/callback/google')

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
    createBindings(bindingOverrides),
  )
}

async function getAuthEvents(): Promise<AuthEventRow[]> {
  const result = await env.DB.prepare(
    `SELECT event_type, provider, user_id, google_issuer, google_sub,
            client_id, redirect_uri, success, reason
     FROM auth_events
     ORDER BY id`,
  ).all<AuthEventRow>()

  return result.results
}

async function countAuthCodes(): Promise<number> {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS count FROM auth_codes`,
  ).first<{ count: number }>()

  return row?.count ?? 0
}

const UPSTREAM_STATE = 'google-upstream-state'

describe('GET /callback/google', () => {
  beforeEach(async () => {
    await insertClientAndState()
  })

  it('creates a user and identity, issues an auth code, and preserves client state', async () => {
    await insertUser(USER_ID)
    await insertAllowlist()

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
      `SELECT google_issuer, google_sub, user_id
       FROM google_identities
       WHERE google_issuer = ? AND google_sub = ?`,
    )
      .bind(GOOGLE_ISSUER, GOOGLE_SUB)
      .first<{ google_issuer: string; google_sub: string; user_id: string }>()

    expect(identity).not.toBeNull()
    expect(identity!.user_id).toBe(USER_ID)

    const storedCode = await env.DB.prepare(
      `SELECT code_hash, user_id, nonce, code_challenge
       FROM auth_codes`,
    ).first<AuthCodeRow>()

    expect(storedCode).not.toBeNull()
    expect(storedCode!.user_id).toBe(USER_ID)
    expect(storedCode!.nonce).toBe(NONCE)
    expect(storedCode!.code_challenge).toBe(CODE_CHALLENGE)
    await expect(
      hashAuthToken(authCode ?? '', TOKEN_HASH_SECRET, 'auth-code'),
    ).resolves.toBe(storedCode!.code_hash)

    const events = await getAuthEvents()
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      event_type: 'callback',
      provider: 'google',
      user_id: USER_ID,
      google_issuer: GOOGLE_ISSUER,
      google_sub: GOOGLE_SUB,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      success: 1,
    })
  })

  it('updates last_seen_at for an existing matching identity', async () => {
    await insertUser(USER_ID)
    await insertAllowlist()
    await env.DB.prepare(
      `INSERT INTO google_identities
         (google_issuer, google_sub, user_id, created_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
      .bind(GOOGLE_ISSUER, GOOGLE_SUB, USER_ID, NOW, NOW)
      .run()

    const { app } = createTestApp()
    const response = await requestCallback(app)

    expect(response.status).toBe(302)

    const identity = await env.DB.prepare(
      `SELECT last_seen_at
       FROM google_identities
       WHERE google_issuer = ? AND google_sub = ?`,
    )
      .bind(GOOGLE_ISSUER, GOOGLE_SUB)
      .first<{ last_seen_at: number }>()

    expect(identity?.last_seen_at).toBeGreaterThan(NOW)
  })

  it('rejects a Google state consumed by the GitHub callback', async () => {
    const response = await gateApp.request(
      `https://auth.example.com/callback/github?code=${GOOGLE_CODE}&state=${UPSTREAM_STATE}`,
      {},
      createBindings(),
    )

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({ error: 'invalid_request' })

    const stateCount = await env.DB.prepare(
      'SELECT COUNT(*) AS count FROM oauth_states',
    ).first<{ count: number }>()
    expect(stateCount?.count).toBe(1)
  })

  it('rejects a reused state before calling Google', async () => {
    await insertUser(USER_ID)
    await insertAllowlist()
    const { app, authenticate } = createTestApp()

    expect((await requestCallback(app)).status).toBe(302)
    const secondResponse = await requestCallback(app)

    expect(secondResponse.status).toBe(400)
    await expect(secondResponse.json()).resolves.toEqual({
      error: 'invalid_request',
    })
    expect(authenticate).toHaveBeenCalledTimes(1)
  })

  it('rejects an expired state before calling Google', async () => {
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
    ['missing state', { code: GOOGLE_CODE }],
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

  it('redirects a Google authentication failure without creating credentials', async () => {
    const authenticate = vi
      .fn()
      .mockRejectedValue(new GoogleAuthError('invalid_hosted_domain'))
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
      reason: 'invalid_hosted_domain',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
    })
  })

  it('rejects an email that is not in the allowlist', async () => {
    await insertUser(USER_ID)
    const { app } = createTestApp()

    const response = await requestCallback(app)

    expect(response.status).toBe(302)
    const location = new URL(response.headers.get('location') ?? '')
    expect(location.searchParams.get('error')).toBe('access_denied')
    await expect(countAuthCodes()).resolves.toBe(0)

    const events = await getAuthEvents()
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      success: 0,
      reason: 'not_in_allowlist',
      google_issuer: GOOGLE_ISSUER,
      google_sub: GOOGLE_SUB,
    })
  })

  it('rejects a disabled allowlist entry', async () => {
    await insertUser(USER_ID)
    await insertAllowlist(GOOGLE_EMAIL, USER_ID, { disabled: true })

    const { app } = createTestApp()
    const response = await requestCallback(app)

    expect(response.status).toBe(302)
    const location = new URL(response.headers.get('location') ?? '')
    expect(location.searchParams.get('error')).toBe('access_denied')
    await expect(countAuthCodes()).resolves.toBe(0)

    const events = await getAuthEvents()
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      success: 0,
      reason: 'not_in_allowlist',
    })
  })

  it('matches an allowlist row stored with a previous pepper version', async () => {
    await insertUser(USER_ID)
    await insertAllowlist(GOOGLE_EMAIL, USER_ID, { pepperVersion: 2 })

    const { app } = createTestApp()
    const response = await requestCallback(
      app,
      undefined,
      createBindings({
        EMAIL_HASH_PEPPER_V2: 'pepper-v2-secret-32-bytes-long!',
        CURRENT_EMAIL_HASH_PEPPER_VERSION: '1',
      }),
    )

    expect(response.status).toBe(302)
    expect(
      new URL(response.headers.get('location') ?? '').searchParams.get('code'),
    ).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it('rejects an identity collision without moving the identity', async () => {
    const allowlistUserId = 'allowlist-user-id'
    const existingUserId = 'existing-user-id'
    await env.DB.prepare(
      `INSERT INTO users (id, created_at, updated_at) VALUES (?, ?, ?)`,
    )
      .bind(allowlistUserId, NOW, NOW)
      .run()
    await env.DB.prepare(
      `INSERT INTO users (id, created_at, updated_at) VALUES (?, ?, ?)`,
    )
      .bind(existingUserId, NOW, NOW)
      .run()
    await insertAllowlist(GOOGLE_EMAIL, allowlistUserId)
    await env.DB.prepare(
      `INSERT INTO google_identities
         (google_issuer, google_sub, user_id, created_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
      .bind(GOOGLE_ISSUER, GOOGLE_SUB, existingUserId, NOW, NOW)
      .run()

    const { app } = createTestApp()
    const response = await requestCallback(app)

    expect(response.status).toBe(302)
    const location = new URL(response.headers.get('location') ?? '')
    expect(location.searchParams.get('error')).toBe('access_denied')
    await expect(countAuthCodes()).resolves.toBe(0)

    const identity = await env.DB.prepare(
      `SELECT user_id
       FROM google_identities
       WHERE google_issuer = ? AND google_sub = ?`,
    )
      .bind(GOOGLE_ISSUER, GOOGLE_SUB)
      .first<{ user_id: string }>()

    expect(identity?.user_id).toBe(existingUserId)

    const events = await getAuthEvents()
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      success: 0,
      reason: 'identity_collision',
      user_id: existingUserId,
      google_issuer: GOOGLE_ISSUER,
      google_sub: GOOGLE_SUB,
    })
  })

  it('canonicalizes issuer aliases when detecting collisions', async () => {
    const allowlistUserId = 'allowlist-user-id'
    const existingUserId = 'existing-user-id'
    await env.DB.prepare(
      `INSERT INTO users (id, created_at, updated_at) VALUES (?, ?, ?)`,
    )
      .bind(allowlistUserId, NOW, NOW)
      .run()
    await env.DB.prepare(
      `INSERT INTO users (id, created_at, updated_at) VALUES (?, ?, ?)`,
    )
      .bind(existingUserId, NOW, NOW)
      .run()
    await insertAllowlist(GOOGLE_EMAIL, allowlistUserId)
    await env.DB.prepare(
      `INSERT INTO google_identities
         (google_issuer, google_sub, user_id, created_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
      .bind(GOOGLE_ISSUER, GOOGLE_SUB, existingUserId, NOW, NOW)
      .run()

    const { app } = createTestApp(
      vi.fn().mockResolvedValue({
        issuer: 'accounts.google.com',
        sub: GOOGLE_SUB,
        email: GOOGLE_EMAIL,
        hd: GOOGLE_HD,
      }),
    )
    const response = await requestCallback(app)

    expect(response.status).toBe(302)
    expect(
      new URL(response.headers.get('location') ?? '').searchParams.get('error'),
    ).toBe('access_denied')
    await expect(countAuthCodes()).resolves.toBe(0)

    const events = await getAuthEvents()
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      success: 0,
      reason: 'identity_collision',
      google_issuer: GOOGLE_ISSUER,
      google_sub: GOOGLE_SUB,
    })
  })

  it('stores the canonical issuer when the callback receives an alias', async () => {
    await insertUser(USER_ID)
    await insertAllowlist()

    const { app } = createTestApp(
      vi.fn().mockResolvedValue({
        issuer: 'accounts.google.com',
        sub: GOOGLE_SUB,
        email: GOOGLE_EMAIL,
        hd: GOOGLE_HD,
      }),
    )
    const response = await requestCallback(app)

    expect(response.status).toBe(302)

    const identity = await env.DB.prepare(
      `SELECT google_issuer, google_sub, user_id
       FROM google_identities
       WHERE google_sub = ?`,
    )
      .bind(GOOGLE_SUB)
      .first<{ google_issuer: string; google_sub: string; user_id: string }>()

    expect(identity).not.toBeNull()
    expect(identity!.google_issuer).toBe(GOOGLE_ISSUER)
    expect(identity!.user_id).toBe(USER_ID)
  })

  it('does not store callback secrets or email in audit events', async () => {
    await insertUser(USER_ID)
    await insertAllowlist()
    const authenticate = vi
      .fn()
      .mockRejectedValue(new GoogleAuthError('token_exchange_failed'))
    const { app } = createTestApp(authenticate)

    await requestCallback(app)

    const serializedEvents = JSON.stringify(await getAuthEvents())
    expect(serializedEvents).not.toContain(GOOGLE_CODE)
    expect(serializedEvents).not.toContain(UPSTREAM_STATE)
    expect(serializedEvents).not.toContain(GOOGLE_CLIENT_SECRET)
    expect(serializedEvents).not.toContain(GOOGLE_EMAIL)
    expect(serializedEvents).not.toContain(normalizeEmail(GOOGLE_EMAIL))
  })

  it('does not include email or email hash in the callback response', async () => {
    await insertUser(USER_ID)
    await insertAllowlist()
    const { app } = createTestApp()

    const response = await requestCallback(app)
    const body = await response.text()

    expect(body).not.toContain(GOOGLE_EMAIL)
    expect(body).not.toContain(normalizeEmail(GOOGLE_EMAIL))
  })
})
