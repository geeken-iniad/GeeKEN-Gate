import { env } from 'cloudflare:workers'
import { beforeEach, describe, expect, it } from 'vitest'

import type { AppBindings } from '../src/lib/config'
import { hashAuthToken } from '../src/lib/crypto'
import { app } from '../src/index'
import { allowingRateLimiter } from './rate-limit'

const NOW = 1_700_000_000
const SESSION_SECRET = 's'.repeat(32)
const SESSION = 'session-value'
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
): Promise<void> {
  const sessionHash = await hashAuthToken(
    SESSION,
    SESSION_SECRET,
    'session',
  )

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO users
         (github_id, github_login, created_at, updated_at)
       VALUES (?, ?, ?, ?)`,
    ).bind(GITHUB_ID, GITHUB_LOGIN, NOW, NOW),
    env.DB.prepare(
      `INSERT INTO sessions
         (session_hash, github_id, created_at, expires_at)
       VALUES (?, ?, ?, ?)`,
    ).bind(sessionHash, GITHUB_ID, NOW, expiresAt),
  ])
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

  it('rejects a frozen user and expires the session cookie', async () => {
    await env.DB.prepare(
      `INSERT INTO frozen_users (github_id, frozen_at, reason)
       VALUES (?, ?, ?)`,
    )
      .bind(GITHUB_ID, NOW, 'manual freeze')
      .run()

    const response = await requestSession()

    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toEqual({
      error: 'access_denied',
    })
    expectExpiredSessionCookie(response)
    expect(await countSessions()).toBe(1)
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
