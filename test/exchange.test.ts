import { env } from 'cloudflare:workers'
import { beforeEach, describe, expect, it } from 'vitest'

import type { AppBindings } from '../src/lib/config'
import {
  hashAuthToken,
  hashClientSecret,
} from '../src/lib/crypto'
import { app } from '../src/index'

const NOW = 1_700_000_000
const CLIENT_ID = 'client-a'
const CLIENT_SECRET = 'client-secret'
const REDIRECT_URI = 'https://client.example/callback'
const AUTH_CODE = 'authorization-code'
const SESSION_SECRET = 'test-session-secret'
const GITHUB_ID = '123456'
const GITHUB_LOGIN = 'octocat'

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
    GITHUB_CLIENT_ID: 'github-client-id',
    GITHUB_CLIENT_SECRET: 'github-client-secret',
    GITHUB_ORG: 'example-org',
    GITHUB_CALLBACK_URL: 'https://auth.example.com/callback',
    SESSION_SECRET,
  }
}

function createBasicAuthorization(
  clientId = CLIENT_ID,
  clientSecret = CLIENT_SECRET,
): string {
  return `Basic ${btoa(`${clientId}:${clientSecret}`)}`
}

async function insertAuthenticationCode(
  options: {
    clientId?: string
    clientSecret?: string
    redirectUri?: string
    code?: string
    expiresAt?: number
  } = {},
): Promise<void> {
  const clientId = options.clientId ?? CLIENT_ID
  const clientSecret = options.clientSecret ?? CLIENT_SECRET
  const redirectUri = options.redirectUri ?? REDIRECT_URI
  const code = options.code ?? AUTH_CODE
  const expiresAt =
    options.expiresAt ?? Math.floor(Date.now() / 1000) + 2 * 60
  const [clientSecretHash, codeHash] = await Promise.all([
    hashClientSecret(clientSecret),
    hashAuthToken(code, SESSION_SECRET, 'auth-code'),
  ])

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO users
         (github_id, github_login, created_at, updated_at)
       VALUES (?, ?, ?, ?)`,
    ).bind(GITHUB_ID, GITHUB_LOGIN, NOW, NOW),
    env.DB.prepare(
      `INSERT INTO clients
         (client_id, client_secret_hash, created_at)
       VALUES (?, ?, ?)`,
    ).bind(clientId, clientSecretHash, NOW),
    env.DB.prepare(
      `INSERT INTO allowed_redirect_uris
         (client_id, redirect_uri, created_at)
       VALUES (?, ?, ?)`,
    ).bind(clientId, redirectUri, NOW),
    env.DB.prepare(
      `INSERT INTO auth_codes
         (code_hash, github_id, client_id, redirect_uri, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(codeHash, GITHUB_ID, clientId, redirectUri, NOW, expiresAt),
  ])
}

async function requestExchange(
  options: {
    authorization?: string | null
    contentType?: string | null
    body?: string
  } = {},
): Promise<Response> {
  const headers = new Headers({
    'CF-Connecting-IP': '203.0.113.20',
    'User-Agent': 'exchange-test-agent',
  })
  const authorization =
    options.authorization === undefined
      ? createBasicAuthorization()
      : options.authorization
  const contentType =
    options.contentType === undefined
      ? 'application/x-www-form-urlencoded'
      : options.contentType

  if (authorization !== null) {
    headers.set('Authorization', authorization)
  }

  if (contentType !== null) {
    headers.set('Content-Type', contentType)
  }

  return app.request(
    'https://auth.example.com/exchange',
    {
      method: 'POST',
      headers,
      body:
        options.body ??
        new URLSearchParams({
          code: AUTH_CODE,
          redirect_uri: REDIRECT_URI,
        }).toString(),
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

describe('POST /exchange', () => {
  beforeEach(async () => {
    await insertAuthenticationCode()
  })

  it('exchanges a valid one-time code for GitHub user information', async () => {
    const response = await requestExchange({
      contentType: 'application/x-www-form-urlencoded; charset=UTF-8',
    })

    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toBe('no-store')
    await expect(response.json()).resolves.toEqual({
      github_id: GITHUB_ID,
      github_login: GITHUB_LOGIN,
    })
    expect(await countRows('auth_codes')).toBe(0)
    await expect(getAuthEvents()).resolves.toEqual([
      {
        event_type: 'exchange',
        github_id: GITHUB_ID,
        github_login: GITHUB_LOGIN,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        success: 1,
        reason: null,
        ip_address: '203.0.113.20',
        user_agent: 'exchange-test-agent',
      },
    ])
  })

  it('rejects reuse of a consumed code', async () => {
    expect((await requestExchange()).status).toBe(200)

    const response = await requestExchange()

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({
      error: 'invalid_grant',
    })
    const events = await getAuthEvents()
    expect(events).toHaveLength(2)
    expect(events[1]).toMatchObject({
      success: 0,
      reason: 'invalid_code',
    })
  })

  it.each([
    ['missing authorization', null],
    ['wrong scheme', 'Bearer token'],
    ['invalid base64', 'Basic !!!'],
    ['missing separator', `Basic ${btoa('client-secret')}`],
    ['empty client ID', `Basic ${btoa(':client-secret')}`],
    ['empty client secret', `Basic ${btoa('client-a:')}`],
  ])('rejects %s', async (_caseName, authorization) => {
    const response = await requestExchange({ authorization })

    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toBe(
      'Basic realm="exchange"',
    )
    await expect(response.json()).resolves.toEqual({
      error: 'invalid_client',
    })
    expect(await countRows('auth_codes')).toBe(1)
  })

  it.each([
    ['an unknown client', 'unknown-client', CLIENT_SECRET],
    ['an incorrect secret', CLIENT_ID, 'wrong-secret'],
  ])('rejects %s', async (_caseName, clientId, clientSecret) => {
    const response = await requestExchange({
      authorization: createBasicAuthorization(clientId, clientSecret),
    })

    expect(response.status).toBe(401)
    await expect(response.json()).resolves.toEqual({
      error: 'invalid_client',
    })
    expect(await countRows('auth_codes')).toBe(1)
    await expect(getAuthEvents()).resolves.toEqual([
      expect.objectContaining({
        client_id: clientId,
        success: 0,
        reason: 'invalid_client',
      }),
    ])
  })

  it('rejects a disabled client', async () => {
    await env.DB.prepare(
      `UPDATE clients
       SET disabled_at = ?
       WHERE client_id = ?`,
    )
      .bind(NOW + 1, CLIENT_ID)
      .run()

    const response = await requestExchange()

    expect(response.status).toBe(401)
    await expect(response.json()).resolves.toEqual({
      error: 'invalid_client',
    })
    expect(await countRows('auth_codes')).toBe(1)
  })

  it.each([
    ['missing content type', null],
    ['JSON content type', 'application/json'],
    ['multipart content type', 'multipart/form-data'],
  ])('rejects %s', async (_caseName, contentType) => {
    const response = await requestExchange({ contentType })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({
      error: 'invalid_request',
    })
    expect(await countRows('auth_codes')).toBe(1)
  })

  it.each([
    ['missing code', new URLSearchParams({ redirect_uri: REDIRECT_URI })],
    ['empty code', new URLSearchParams({ code: '', redirect_uri: REDIRECT_URI })],
    ['missing redirect URI', new URLSearchParams({ code: AUTH_CODE })],
    [
      'duplicate code',
      new URLSearchParams([
        ['code', AUTH_CODE],
        ['code', AUTH_CODE],
        ['redirect_uri', REDIRECT_URI],
      ]),
    ],
    [
      'duplicate redirect URI',
      new URLSearchParams([
        ['code', AUTH_CODE],
        ['redirect_uri', REDIRECT_URI],
        ['redirect_uri', REDIRECT_URI],
      ]),
    ],
  ])('rejects a form with %s', async (_caseName, form) => {
    const response = await requestExchange({ body: form.toString() })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({
      error: 'invalid_request',
    })
    expect(await countRows('auth_codes')).toBe(1)
  })

  it('rejects a code issued to another client', async () => {
    const secondClientSecret = 'second-client-secret'
    const secondClientSecretHash = await hashClientSecret(secondClientSecret)
    await env.DB.prepare(
      `INSERT INTO clients
         (client_id, client_secret_hash, created_at)
       VALUES (?, ?, ?)`,
    )
      .bind('client-b', secondClientSecretHash, NOW)
      .run()

    const response = await requestExchange({
      authorization: createBasicAuthorization(
        'client-b',
        secondClientSecret,
      ),
    })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({
      error: 'invalid_grant',
    })
    expect(await countRows('auth_codes')).toBe(1)
  })

  it('rejects a redirect URI that does not exactly match', async () => {
    const response = await requestExchange({
      body: new URLSearchParams({
        code: AUTH_CODE,
        redirect_uri: `${REDIRECT_URI}/extra`,
      }).toString(),
    })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({
      error: 'invalid_grant',
    })
    expect(await countRows('auth_codes')).toBe(1)
  })

  it('rejects an expired code', async () => {
    await env.DB.prepare('UPDATE auth_codes SET expires_at = ?')
      .bind(Math.floor(Date.now() / 1000) - 1)
      .run()

    const response = await requestExchange()

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({
      error: 'invalid_grant',
    })
    expect(await countRows('auth_codes')).toBe(1)
  })

  it('rejects a frozen user and consumes the one-time code', async () => {
    await env.DB.prepare(
      `INSERT INTO frozen_users (github_id, frozen_at, reason)
       VALUES (?, ?, ?)`,
    )
      .bind(GITHUB_ID, NOW, 'manual freeze')
      .run()

    const response = await requestExchange()

    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toEqual({
      error: 'access_denied',
    })
    expect(await countRows('auth_codes')).toBe(0)
    await expect(getAuthEvents()).resolves.toEqual([
      expect.objectContaining({
        github_id: GITHUB_ID,
        github_login: GITHUB_LOGIN,
        success: 0,
        reason: 'frozen_user',
      }),
    ])
  })

  it('does not expose or audit the code or client secret', async () => {
    const response = await requestExchange({
      body: new URLSearchParams({
        code: 'wrong-authorization-code',
        redirect_uri: REDIRECT_URI,
      }).toString(),
    })
    const responseBody = await response.text()
    const serializedEvents = JSON.stringify(await getAuthEvents())

    expect(responseBody).not.toContain(AUTH_CODE)
    expect(responseBody).not.toContain(CLIENT_SECRET)
    expect(serializedEvents).not.toContain(AUTH_CODE)
    expect(serializedEvents).not.toContain('wrong-authorization-code')
    expect(serializedEvents).not.toContain(CLIENT_SECRET)
  })
})
