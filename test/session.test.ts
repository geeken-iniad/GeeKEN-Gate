import { env } from 'cloudflare:workers'
import { beforeEach, describe, expect, it } from 'vitest'

import type { AppBindings } from '../src/lib/config'
import { hashAuthToken } from '../src/lib/crypto'
import { app } from '../src/index'
import { allowingRateLimiter } from './rate-limit'

const NOW = 1_700_000_000
const SESSION_SECRET = 's'.repeat(32)
const SESSION = 'session-value'
const USER_ID = 'user-123'
const GITHUB_ID = '123456'
const GITHUB_LOGIN = 'octocat'

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

async function insertSession(
  expiresAt = Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
  options: {
    memberStatus?: 'active' | 'suspended' | 'left'
    memberEmailLoginAllowed?: 0 | 1
  } = {},
): Promise<void> {
  const sessionHash = await hashAuthToken(
    SESSION,
    SESSION_SECRET,
    'session',
  )

  const statements: D1PreparedStatement[] = []

  if (options.memberStatus) {
    statements.push(
      env.DB.prepare(
        `INSERT INTO members (member_id, display_name, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).bind('member-a', 'Octo Cat', options.memberStatus, NOW, NOW),
    )
  }

  if (options.memberEmailLoginAllowed !== undefined) {
    statements.push(
      env.DB.prepare(
        `INSERT INTO member_emails
           (normalized_email, member_id, login_allowed, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).bind(
        'octo@example.com',
        'member-a',
        options.memberEmailLoginAllowed,
        NOW,
        NOW,
      ),
    )
  }

  statements.push(
    env.DB.prepare(
      `INSERT INTO users
         (user_id, member_id, created_at, updated_at)
       VALUES (?, ?, ?, ?)`,
    ).bind(USER_ID, options.memberStatus ? 'member-a' : null, NOW, NOW),
    env.DB.prepare(
      `INSERT INTO external_identities
         (provider, provider_user_id, user_id, provider_login, email, created_at, updated_at)
       VALUES ('github', ?, ?, ?, ?, ?, ?)`,
    ).bind(GITHUB_ID, USER_ID, GITHUB_LOGIN, 'octo@example.com', NOW, NOW),
    env.DB.prepare(
      `INSERT INTO sessions
         (session_hash, user_id, created_at, expires_at)
       VALUES (?, ?, ?, ?)`,
    ).bind(sessionHash, USER_ID, NOW, expiresAt),
  )

  await env.DB.batch(statements)
}

async function requestSession(session: string | null = SESSION) {
  const headers = new Headers()

  if (session !== null) {
    headers.set('Cookie', `giken_session=${session}`)
  }

  return app.request(
    'https://auth.example.com/session',
    { headers },
    createBindings(),
  )
}

async function requestLogout(session: string | null = SESSION) {
  const headers = new Headers()

  if (session !== null) {
    headers.set('Cookie', `giken_session=${session}`)
  }

  return app.request(
    'https://auth.example.com/logout',
    {
      method: 'POST',
      headers,
    },
    createBindings(),
  )
}

async function countSessions(): Promise<number> {
  const row = await env.DB.prepare(
    'SELECT COUNT(*) AS count FROM sessions',
  ).first<{ count: number }>()

  return row?.count ?? 0
}

function expectExpiredSessionCookie(response: Response): void {
  const setCookie = response.headers.get('set-cookie') ?? ''

  expect(setCookie).toContain('giken_session=')
  expect(setCookie).toContain('Max-Age=0')
  expect(setCookie).toContain('Path=/')
  expect(setCookie).toContain('HttpOnly')
  expect(setCookie).toContain('Secure')
  expect(setCookie).toContain('SameSite=Lax')
}

describe('GET /session', () => {
  beforeEach(async () => {
    await insertSession()
  })

  it('returns the user for a valid session', async () => {
    const response = await requestSession()

    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(response.headers.get('set-cookie')).toBeNull()
    await expect(response.json()).resolves.toEqual({
      user_id: USER_ID,
      github_id: GITHUB_ID,
      github_login: GITHUB_LOGIN,
    })
    expect(await countSessions()).toBe(1)
  })

  it('rejects a missing session cookie', async () => {
    const response = await requestSession(null)

    expect(response.status).toBe(401)
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(response.headers.get('set-cookie')).toBeNull()
    await expect(response.json()).resolves.toEqual({
      error: 'unauthorized',
    })
    expect(await countSessions()).toBe(1)
  })

  it('rejects an unknown session and expires its cookie', async () => {
    const response = await requestSession('unknown-session')

    expect(response.status).toBe(401)
    await expect(response.json()).resolves.toEqual({
      error: 'unauthorized',
    })
    expectExpiredSessionCookie(response)
    expect(await countSessions()).toBe(1)
  })

  it('rejects an expired session and expires its cookie', async () => {
    await env.DB.prepare('UPDATE sessions SET expires_at = ?')
      .bind(Math.floor(Date.now() / 1000) - 1)
      .run()

    const response = await requestSession()

    expect(response.status).toBe(401)
    await expect(response.json()).resolves.toEqual({
      error: 'unauthorized',
    })
    expectExpiredSessionCookie(response)
    expect(await countSessions()).toBe(1)
  })

  it('rejects a disabled user and expires the session cookie', async () => {
    await env.DB.prepare(
      `UPDATE users SET disabled_at = ? WHERE user_id = ?`,
    )
      .bind(NOW, USER_ID)
      .run()

    const response = await requestSession()

    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toEqual({
      error: 'access_denied',
    })
    expectExpiredSessionCookie(response)
    expect(await countSessions()).toBe(1)
  })

  it('rejects a suspended member and expires the session cookie', async () => {
    await env.DB.prepare('DELETE FROM sessions').run()
    await env.DB.prepare('DELETE FROM external_identities').run()
    await env.DB.prepare('DELETE FROM users').run()
    await insertSession(undefined, { memberStatus: 'suspended' })

    const response = await requestSession()

    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toEqual({ error: 'access_denied' })
    expectExpiredSessionCookie(response)
  })

  it('rejects a disallowed member email when present', async () => {
    await env.DB.prepare('DELETE FROM sessions').run()
    await env.DB.prepare('DELETE FROM external_identities').run()
    await env.DB.prepare('DELETE FROM users').run()
    await insertSession(undefined, {
      memberStatus: 'active',
      memberEmailLoginAllowed: 0,
    })

    const response = await requestSession()

    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toEqual({ error: 'access_denied' })
    expectExpiredSessionCookie(response)
  })
})

describe('POST /logout', () => {
  beforeEach(async () => {
    await insertSession()
  })

  it('deletes the current session and expires its cookie', async () => {
    const response = await requestLogout()

    expect(response.status).toBe(204)
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(await response.text()).toBe('')
    expectExpiredSessionCookie(response)
    expect(await countSessions()).toBe(0)

    const sessionResponse = await requestSession()
    expect(sessionResponse.status).toBe(401)
  })

  it('does not delete another session for an unknown cookie', async () => {
    const response = await requestLogout('unknown-session')

    expect(response.status).toBe(204)
    expectExpiredSessionCookie(response)
    expect(await countSessions()).toBe(1)
  })

  it('is idempotent without a session cookie', async () => {
    const firstResponse = await requestLogout(null)
    const secondResponse = await requestLogout(null)

    expect(firstResponse.status).toBe(204)
    expect(secondResponse.status).toBe(204)
    expectExpiredSessionCookie(firstResponse)
    expectExpiredSessionCookie(secondResponse)
    expect(await countSessions()).toBe(1)
  })
})
