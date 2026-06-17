import { env } from 'cloudflare:workers'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { generateCodeChallenge, hashAuthToken } from '../src/lib/crypto'
import { app } from '../src/index'
import {
  CLIENT_ID,
  CODE_VERIFIER,
  GITHUB_ID,
  GITHUB_LOGIN,
  NONCE,
  REDIRECT_URI,
  TOKEN_HASH_SECRET,
  USER_ID,
  createBindings,
  countRows,
  insertAuthCode,
  insertClient,
  insertRefreshToken,
  insertUser,
} from './oidc-helpers'

const AUTH_CODE = 'authorization-code'
const REFRESH_TOKEN = 'refresh-token-value'
const ANOTHER_CLIENT_ID = 'client-b'

async function hashToken(
  value: string,
  purpose: 'auth-code' | 'access-token' | 'refresh-token',
): Promise<string> {
  return hashAuthToken(value, TOKEN_HASH_SECRET, purpose)
}

function decodeJwt(jwt: string): {
  header: Record<string, unknown>
  payload: Record<string, unknown>
} {
  const [headerB64, payloadB64] = jwt.split('.')
  const headerJson = atob(
    headerB64!.replaceAll('-', '+').replaceAll('_', '/'),
  )
  const payloadJson = atob(
    payloadB64!.replaceAll('-', '+').replaceAll('_', '/'),
  )

  return {
    header: JSON.parse(headerJson),
    payload: JSON.parse(payloadJson),
  }
}

async function requestToken(
  body: Record<string, string>,
  bindingOverrides = {},
): Promise<Response> {
  return app.request(
    'https://auth.example.com/token',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'CF-Connecting-IP': '203.0.113.20',
        'User-Agent': 'token-test-agent',
      },
      body: new URLSearchParams(body).toString(),
    },
    createBindings(bindingOverrides),
  )
}

async function getAuthEvents(): Promise<
  {
    event_type: string
    provider: string | null
    user_id: string | null
    client_id: string | null
    success: number
    reason: string | null
  }[]
> {
  const result = await env.DB.prepare(
    `SELECT event_type, provider, user_id, client_id, success, reason
     FROM auth_events
     ORDER BY id`,
  ).all<{
    event_type: string
    provider: string | null
    user_id: string | null
    client_id: string | null
    success: number
    reason: string | null
  }>()

  return result.results
}

describe('POST /token', () => {
  let codeChallenge: string

  beforeEach(async () => {
    await insertClient()
    await insertUser()
    codeChallenge = await generateCodeChallenge(CODE_VERIFIER)
  })

  it('exchanges a valid one-time code for tokens', async () => {
    const codeHash = await hashToken(AUTH_CODE, 'auth-code')
    await insertAuthCode(codeHash, {
      userId: USER_ID,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      nonce: NONCE,
      codeChallenge,
    })

    const response = await requestToken({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code: AUTH_CODE,
      code_verifier: CODE_VERIFIER,
    })

    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(response.headers.get('pragma')).toBe('no-cache')

    const body = (await response.json()) as Record<string, unknown>
    expect(body.token_type).toBe('Bearer')
    expect(body.expires_in).toBe(900)
    expect(typeof body.access_token).toBe('string')
    expect(typeof body.refresh_token).toBe('string')
    expect(typeof body.id_token).toBe('string')

    const { header, payload } = decodeJwt(body.id_token as string)
    expect(header).toMatchObject({
      alg: 'RS256',
      typ: 'JWT',
      kid: 'test-key',
    })
    expect(payload.iss).toBe('https://auth.example.com')
    expect(payload.sub).toBe(USER_ID)
    expect(payload.aud).toBe(CLIENT_ID)
    expect(payload.nonce).toBe(NONCE)
    expect(payload.exp).toBeGreaterThan(payload.iat as number)

    expect(await countRows('auth_codes')).toBe(0)
    expect(await countRows('access_tokens')).toBe(1)
    expect(await countRows('refresh_tokens')).toBe(1)

    const events = await getAuthEvents()
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({
      event_type: 'token',
      provider: 'oidc',
      user_id: USER_ID,
      client_id: CLIENT_ID,
      success: 1,
    })
  })

  it('rejects reuse of a consumed code', async () => {
    const codeHash = await hashToken(AUTH_CODE, 'auth-code')
    await insertAuthCode(codeHash, { codeChallenge })

    expect(
      (
        await requestToken({
          grant_type: 'authorization_code',
          client_id: CLIENT_ID,
          redirect_uri: REDIRECT_URI,
          code: AUTH_CODE,
          code_verifier: CODE_VERIFIER,
        })
      ).status,
    ).toBe(200)

    const response = await requestToken({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code: AUTH_CODE,
      code_verifier: CODE_VERIFIER,
    })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({ error: 'invalid_grant' })
  })

  it('rejects a code with mismatched PKCE', async () => {
    const codeHash = await hashToken(AUTH_CODE, 'auth-code')
    await insertAuthCode(codeHash, { codeChallenge })

    const response = await requestToken({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code: AUTH_CODE,
      code_verifier: 'wrong-verifier',
    })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({ error: 'invalid_grant' })
  })

  it('rejects a code issued to another client', async () => {
    const codeHash = await hashToken(AUTH_CODE, 'auth-code')
    await insertAuthCode(codeHash, { codeChallenge })

    const response = await requestToken({
      grant_type: 'authorization_code',
      client_id: ANOTHER_CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code: AUTH_CODE,
      code_verifier: CODE_VERIFIER,
    })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({ error: 'invalid_grant' })
  })

  it('rejects a code with a mismatched redirect URI', async () => {
    const codeHash = await hashToken(AUTH_CODE, 'auth-code')
    await insertAuthCode(codeHash, { codeChallenge })

    const response = await requestToken({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      redirect_uri: 'https://client.example/other',
      code: AUTH_CODE,
      code_verifier: CODE_VERIFIER,
    })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({ error: 'invalid_grant' })
  })

  it('rejects an expired code', async () => {
    const codeHash = await hashToken(AUTH_CODE, 'auth-code')
    const now = Math.floor(Date.now() / 1000)
    await insertAuthCode(codeHash, {
      codeChallenge,
      createdAt: now - 2,
      expiresAt: now - 1,
    })

    const response = await requestToken({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code: AUTH_CODE,
      code_verifier: CODE_VERIFIER,
    })

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({ error: 'invalid_grant' })
  })

  it.each([
    ['missing grant_type', {}],
    ['unsupported grant_type', { grant_type: 'client_credentials' }],
    [
      'missing code',
      {
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: CODE_VERIFIER,
      },
    ],
    [
      'missing code_verifier',
      {
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code: AUTH_CODE,
      },
    ],
    [
      'missing client_id',
      {
        grant_type: 'authorization_code',
        redirect_uri: REDIRECT_URI,
        code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
      },
    ],
    [
      'missing redirect_uri',
      {
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        code: AUTH_CODE,
        code_verifier: CODE_VERIFIER,
      },
    ],
  ])('rejects %s', async (_caseName, body) => {
    const response = await requestToken(body as Record<string, string>)

    expect(response.status).toBe(400)
    const json = (await response.json()) as { error: string }
    expect(json.error).toMatch(
      /invalid_request|invalid_grant|unsupported_grant_type/,
    )
  })

  it('rejects non-form content type', async () => {
    const response = await app.request(
      'https://auth.example.com/token',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          grant_type: 'authorization_code',
          client_id: CLIENT_ID,
          redirect_uri: REDIRECT_URI,
          code: AUTH_CODE,
          code_verifier: CODE_VERIFIER,
        }),
      },
      createBindings(),
    )

    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toEqual({ error: 'invalid_request' })
  })

  describe('refresh_token grant', () => {
    beforeEach(async () => {
      const refreshHash = await hashToken(REFRESH_TOKEN, 'refresh-token')
      await insertRefreshToken(refreshHash)
    })

    it('issues a new access token and ID token without nonce or refresh token', async () => {
      const response = await requestToken({
        grant_type: 'refresh_token',
        client_id: CLIENT_ID,
        refresh_token: REFRESH_TOKEN,
      })

      expect(response.status).toBe(200)
      expect(response.headers.get('cache-control')).toBe('no-store')

      const body = (await response.json()) as Record<string, unknown>
      expect(body.token_type).toBe('Bearer')
      expect(body.expires_in).toBe(900)
      expect(typeof body.access_token).toBe('string')
      expect(body.refresh_token).toBeUndefined()
      expect(typeof body.id_token).toBe('string')

      const { payload } = decodeJwt(body.id_token as string)
      expect(payload.sub).toBe(USER_ID)
      expect(payload.aud).toBe(CLIENT_ID)
      expect(payload.nonce).toBeUndefined()
      expect(await countRows('refresh_tokens')).toBe(1)
      expect(await countRows('access_tokens')).toBe(1)
    })

    it('rejects a refresh token with mismatched client_id', async () => {
      const response = await requestToken({
        grant_type: 'refresh_token',
        client_id: ANOTHER_CLIENT_ID,
        refresh_token: REFRESH_TOKEN,
      })

      expect(response.status).toBe(400)
      await expect(response.json()).resolves.toEqual({ error: 'invalid_grant' })
    })

    it('rejects an expired refresh token', async () => {
      await env.DB.prepare('DELETE FROM refresh_tokens').run()
      const refreshHash = await hashToken(REFRESH_TOKEN, 'refresh-token')
      const now = Math.floor(Date.now() / 1000)
      await insertRefreshToken(refreshHash, {
        createdAt: now - 2,
        expiresAt: now - 1,
      })

      const response = await requestToken({
        grant_type: 'refresh_token',
        client_id: CLIENT_ID,
        refresh_token: REFRESH_TOKEN,
      })

      expect(response.status).toBe(400)
      await expect(response.json()).resolves.toEqual({ error: 'invalid_grant' })
    })

    it('rejects a revoked refresh token', async () => {
      await env.DB.prepare('DELETE FROM refresh_tokens').run()
      const refreshHash = await hashToken(REFRESH_TOKEN, 'refresh-token')
      const now = Math.floor(Date.now() / 1000)
      await insertRefreshToken(refreshHash, { revokedAt: now })

      const response = await requestToken({
        grant_type: 'refresh_token',
        client_id: CLIENT_ID,
        refresh_token: REFRESH_TOKEN,
      })

      expect(response.status).toBe(400)
      await expect(response.json()).resolves.toEqual({ error: 'invalid_grant' })
    })
  })
})
