import { env } from 'cloudflare:workers'
import { beforeEach, describe, expect, it } from 'vitest'

import { hashAuthToken } from '../src/lib/crypto'
import { app } from '../src/index'
import {
  CLIENT_ID,
  REDIRECT_URI,
  TOKEN_HASH_SECRET,
  USER_ID,
  createBindings,
  insertAccessToken,
  insertClient,
  insertUser,
} from './oidc-helpers'

const ACCESS_TOKEN = 'access-token-value'

async function hashAccessToken(value: string): Promise<string> {
  return hashAuthToken(value, TOKEN_HASH_SECRET, 'access-token')
}

describe('/userinfo', () => {
  beforeEach(async () => {
    await insertClient()
    await insertUser()
    const tokenHash = await hashAccessToken(ACCESS_TOKEN)
    await insertAccessToken(tokenHash)
  })

  it('GET returns only sub for a valid Bearer token', async () => {
    const response = await app.request(
      'https://auth.example.com/userinfo',
      {
        headers: {
          Authorization: `Bearer ${ACCESS_TOKEN}`,
        },
      },
      createBindings(),
    )

    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(response.headers.get('pragma')).toBe('no-cache')
    await expect(response.json()).resolves.toEqual({ sub: USER_ID })
  })

  it('POST returns only sub for a valid form-body token', async () => {
    const response = await app.request(
      'https://auth.example.com/userinfo',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ access_token: ACCESS_TOKEN }).toString(),
      },
      createBindings(),
    )

    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toEqual({ sub: USER_ID })
  })

  it('POST returns only sub for a valid Bearer token', async () => {
    const response = await app.request(
      'https://auth.example.com/userinfo',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${ACCESS_TOKEN}`,
        },
      },
      createBindings(),
    )

    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toEqual({ sub: USER_ID })
  })

  it('rejects a missing token', async () => {
    const response = await app.request(
      'https://auth.example.com/userinfo',
      {},
      createBindings(),
    )

    expect(response.status).toBe(401)
    expect(response.headers.get('www-authenticate')).toContain('invalid_token')
    expect(response.headers.get('cache-control')).toBe('no-store')
    await expect(response.json()).resolves.toEqual({ error: 'invalid_token' })
  })

  it('rejects a query-string token', async () => {
    const response = await app.request(
      `https://auth.example.com/userinfo?access_token=${ACCESS_TOKEN}`,
      {},
      createBindings(),
    )

    expect(response.status).toBe(401)
  })

  it('rejects an unknown token', async () => {
    const response = await app.request(
      'https://auth.example.com/userinfo',
      {
        headers: {
          Authorization: 'Bearer unknown-token',
        },
      },
      createBindings(),
    )

    expect(response.status).toBe(401)
    await expect(response.json()).resolves.toEqual({ error: 'invalid_token' })
  })

  it('rejects a malformed Authorization header', async () => {
    const response = await app.request(
      'https://auth.example.com/userinfo',
      {
        headers: {
          Authorization: `Basic ${btoa('user:pass')}`,
        },
      },
      createBindings(),
    )

    expect(response.status).toBe(401)
  })
})
