import type { Context } from 'hono'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import { hashAuthToken, verifyHashedToken } from '../lib/crypto'

type AppContext = Context<{ Bindings: AppBindings }>

interface AccessTokenRow {
  user_id: string
  token_hash: string
}

function setNoCacheHeaders(c: AppContext): void {
  c.header('Cache-Control', 'no-store')
  c.header('Pragma', 'no-cache')
}

function invalidTokenResponse(c: AppContext, status: 401 | 400 = 401): Response {
  setNoCacheHeaders(c)

  if (status === 401) {
    c.header('WWW-Authenticate', 'Bearer error="invalid_token"')
  }

  return c.json({ error: 'invalid_token' }, status)
}

async function extractAccessToken(c: AppContext): Promise<string | undefined> {
  const header = c.req.header('Authorization')
  const match = header?.match(/^Bearer ([A-Za-z0-9_-]+)$/)

  if (match) {
    return match?.[1]
  }

  if (c.req.method === 'GET') {
    return undefined
  }

  const contentType = c.req.header('Content-Type')
  const mediaType = contentType?.split(';', 1)[0]?.trim().toLowerCase()

  if (mediaType !== 'application/x-www-form-urlencoded') {
    return undefined
  }

  let form: FormData

  try {
    form = await c.req.formData()
  } catch {
    return undefined
  }

  const values = form.getAll('access_token')

  if (values.length !== 1 || typeof values[0] !== 'string') {
    return undefined
  }

  return values[0]
}

export async function handleUserinfo(c: AppContext): Promise<Response> {
  const config = await loadAuthServerConfig(c.env)
  const occurredAt = Math.floor(Date.now() / 1000)
  const accessToken = await extractAccessToken(c)

  if (!accessToken) {
    return invalidTokenResponse(c)
  }

  const tokenHash = await hashAuthToken(
    accessToken,
    config.tokenHashSecret,
    'access-token',
  )
  const row = await config.db
    .prepare(
      `SELECT user_id, token_hash
       FROM access_tokens
       WHERE token_hash = ?
         AND expires_at > ?`,
    )
    .bind(tokenHash, occurredAt)
    .first<AccessTokenRow>()

  if (
    row === null ||
    !(await verifyHashedToken(
      accessToken,
      row.token_hash,
      config.tokenHashSecret,
      'access-token',
    ))
  ) {
    return invalidTokenResponse(c)
  }

  setNoCacheHeaders(c)

  return c.json({ sub: row.user_id })
}
