import type { Context } from 'hono'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import { generateRandomToken, hashAuthToken, verifyHashedToken } from '../lib/crypto'
import { signIdToken, verifyPKCE } from '../lib/oidc'
import { enforceRateLimit, getClientIp } from '../lib/rate-limit'

const ACCESS_TOKEN_LIFETIME_SECONDS = 15 * 60
const REFRESH_TOKEN_LIFETIME_SECONDS = 30 * 24 * 60 * 60
const ID_TOKEN_LIFETIME_SECONDS = 60 * 60

type AppContext = Context<{ Bindings: AppBindings }>
type TokenError = 'invalid_request' | 'invalid_grant' | 'unsupported_grant_type'

interface AuthCodeRow {
  user_id: string
  client_id: string
  redirect_uri: string
  nonce: string
  code_challenge: string
  code_hash: string
}

interface RefreshTokenRow {
  user_id: string
  client_id: string
  token_hash: string
}

interface AuditEvent {
  success: boolean
  provider: string
  grantType?: string
  reason?: string
  clientId?: string
  userId?: string
}

function setNoCacheHeaders(c: AppContext): void {
  c.header('Cache-Control', 'no-store')
  c.header('Pragma', 'no-cache')
}

function tokenError(
  c: AppContext,
  error: TokenError,
  status: 400 | 401 = 400,
): Response {
  setNoCacheHeaders(c)
  return c.json({ error }, status)
}

function getSingleFormValue(form: FormData, name: string): string | undefined {
  const values = form.getAll(name)

  if (values.length !== 1 || typeof values[0] !== 'string') {
    return undefined
  }

  return values[0]
}

function getRequestMetadata(c: AppContext) {
  return {
    ipAddress: c.req.header('CF-Connecting-IP') ?? null,
    userAgent: c.req.header('User-Agent') ?? null,
  }
}

function prepareAuditEvent(
  c: AppContext,
  database: D1Database,
  event: AuditEvent,
  occurredAt: number,
): D1PreparedStatement {
  const { ipAddress, userAgent } = getRequestMetadata(c)

  return database
    .prepare(
      `INSERT INTO auth_events
         (event_type, provider, user_id, google_issuer, google_sub, client_id,
          success, reason, ip_address, user_agent, occurred_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'token',
      event.provider,
      event.userId ?? null,
      null,
      null,
      event.clientId ?? null,
      event.success ? 1 : 0,
      event.reason ?? null,
      ipAddress,
      userAgent,
      occurredAt,
    )
}

async function recordAuditEvent(
  c: AppContext,
  database: D1Database,
  event: AuditEvent,
  occurredAt: number,
): Promise<void> {
  await prepareAuditEvent(c, database, event, occurredAt).run()
}

async function issueIdToken(
  config: Awaited<ReturnType<typeof loadAuthServerConfig>>,
  userId: string,
  clientId: string,
  occurredAt: number,
  nonce?: string,
): Promise<string> {
  return signIdToken(
    {
      iss: config.issuer.href.replace(/\/+$/, ''),
      sub: userId,
      aud: clientId,
      exp: occurredAt + ID_TOKEN_LIFETIME_SECONDS,
      iat: occurredAt,
      nonce,
    },
    config.signingKey,
    config.keyId,
  )
}

async function handleAuthorizationCodeGrant(
  c: AppContext,
  config: Awaited<ReturnType<typeof loadAuthServerConfig>>,
  occurredAt: number,
  form: FormData,
): Promise<Response> {
  const clientId = getSingleFormValue(form, 'client_id')
  const redirectUri = getSingleFormValue(form, 'redirect_uri')
  const code = getSingleFormValue(form, 'code')
  const codeVerifier = getSingleFormValue(form, 'code_verifier')

  if (!clientId || !redirectUri || !code || !codeVerifier) {
    return tokenError(c, 'invalid_request')
  }

  const codeHash = await hashAuthToken(
    code,
    config.tokenHashSecret,
    'auth-code',
  )
  const authCode = await config.db
    .prepare(
      `DELETE FROM auth_codes
       WHERE code_hash = ?
         AND expires_at > ?
       RETURNING user_id, client_id, redirect_uri, nonce, code_challenge, code_hash`,
    )
    .bind(codeHash, occurredAt)
    .first<AuthCodeRow>()

  if (
    authCode === null ||
    !(await verifyHashedToken(
      code,
      authCode.code_hash,
      config.tokenHashSecret,
      'auth-code',
    ))
  ) {
    await recordAuditEvent(
      c,
      config.db,
      {
        success: false,
        provider: 'oidc',
        grantType: 'authorization_code',
        reason: 'invalid_code',
        clientId,
      },
      occurredAt,
    )

    return tokenError(c, 'invalid_grant')
  }

  if (
    authCode.client_id !== clientId ||
    authCode.redirect_uri !== redirectUri
  ) {
    await recordAuditEvent(
      c,
      config.db,
      {
        success: false,
        provider: 'oidc',
        grantType: 'authorization_code',
        reason: 'invalid_code',
        clientId,
        userId: authCode.user_id,
      },
      occurredAt,
    )

    return tokenError(c, 'invalid_grant')
  }

  if (!(await verifyPKCE(codeVerifier, authCode.code_challenge))) {
    await recordAuditEvent(
      c,
      config.db,
      {
        success: false,
        provider: 'oidc',
        grantType: 'authorization_code',
        reason: 'invalid_pkce',
        clientId,
        userId: authCode.user_id,
      },
      occurredAt,
    )

    return tokenError(c, 'invalid_grant')
  }

  const clientRateLimitResponse = await enforceRateLimit(
    c,
    c.env.CLIENT_RATE_LIMITER,
    `token:client:${clientId}`,
    { route: '/token', scope: 'client', clientId },
  )

  if (clientRateLimitResponse !== null) {
    return clientRateLimitResponse
  }

  const accessToken = generateRandomToken()
  const refreshToken = generateRandomToken()
  const [accessHash, refreshHash] = await Promise.all([
    hashAuthToken(accessToken, config.tokenHashSecret, 'access-token'),
    hashAuthToken(refreshToken, config.tokenHashSecret, 'refresh-token'),
  ])

  const idToken = await issueIdToken(
    config,
    authCode.user_id,
    clientId,
    occurredAt,
    authCode.nonce,
  )

  await config.db.batch([
    config.db
      .prepare(
        `INSERT INTO access_tokens
           (token_hash, user_id, client_id, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(
        accessHash,
        authCode.user_id,
        clientId,
        occurredAt,
        occurredAt + ACCESS_TOKEN_LIFETIME_SECONDS,
      ),
    config.db
      .prepare(
        `INSERT INTO refresh_tokens
           (token_hash, user_id, client_id, created_at, expires_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        refreshHash,
        authCode.user_id,
        clientId,
        occurredAt,
        occurredAt + REFRESH_TOKEN_LIFETIME_SECONDS,
        null,
      ),
    prepareAuditEvent(
      c,
      config.db,
      {
        success: true,
        provider: 'oidc',
        grantType: 'authorization_code',
        clientId,
        userId: authCode.user_id,
      },
      occurredAt,
    ),
  ])

  setNoCacheHeaders(c)

  return c.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_LIFETIME_SECONDS,
    id_token: idToken,
    refresh_token: refreshToken,
  })
}

async function handleRefreshTokenGrant(
  c: AppContext,
  config: Awaited<ReturnType<typeof loadAuthServerConfig>>,
  occurredAt: number,
  form: FormData,
): Promise<Response> {
  const clientId = getSingleFormValue(form, 'client_id')
  const refreshToken = getSingleFormValue(form, 'refresh_token')

  if (!clientId || !refreshToken) {
    return tokenError(c, 'invalid_request')
  }

  const tokenHash = await hashAuthToken(
    refreshToken,
    config.tokenHashSecret,
    'refresh-token',
  )
  const refreshRow = await config.db
    .prepare(
      `SELECT user_id, client_id, token_hash
       FROM refresh_tokens
       WHERE token_hash = ?
         AND expires_at > ?
         AND revoked_at IS NULL`,
    )
    .bind(tokenHash, occurredAt)
    .first<RefreshTokenRow>()

  if (
    refreshRow === null ||
    !(await verifyHashedToken(
      refreshToken,
      refreshRow.token_hash,
      config.tokenHashSecret,
      'refresh-token',
    ))
  ) {
    await recordAuditEvent(
      c,
      config.db,
      {
        success: false,
        provider: 'oidc',
        grantType: 'refresh_token',
        reason: 'invalid_refresh_token',
        clientId,
      },
      occurredAt,
    )

    return tokenError(c, 'invalid_grant')
  }

  if (refreshRow.client_id !== clientId) {
    await recordAuditEvent(
      c,
      config.db,
      {
        success: false,
        provider: 'oidc',
        grantType: 'refresh_token',
        reason: 'client_mismatch',
        clientId,
        userId: refreshRow.user_id,
      },
      occurredAt,
    )

    return tokenError(c, 'invalid_grant')
  }

  const clientRateLimitResponse = await enforceRateLimit(
    c,
    c.env.CLIENT_RATE_LIMITER,
    `token:client:${clientId}`,
    { route: '/token', scope: 'client', clientId },
  )

  if (clientRateLimitResponse !== null) {
    return clientRateLimitResponse
  }

  const accessToken = generateRandomToken()
  const accessHash = await hashAuthToken(
    accessToken,
    config.tokenHashSecret,
    'access-token',
  )

  const idToken = await issueIdToken(
    config,
    refreshRow.user_id,
    clientId,
    occurredAt,
  )

  await config.db
    .prepare(
      `INSERT INTO access_tokens
         (token_hash, user_id, client_id, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .bind(
      accessHash,
      refreshRow.user_id,
      clientId,
      occurredAt,
      occurredAt + ACCESS_TOKEN_LIFETIME_SECONDS,
    )
    .run()

  await recordAuditEvent(
    c,
    config.db,
    {
      success: true,
      provider: 'oidc',
      grantType: 'refresh_token',
      clientId,
      userId: refreshRow.user_id,
    },
    occurredAt,
  )

  setNoCacheHeaders(c)

  return c.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_LIFETIME_SECONDS,
    id_token: idToken,
  })
}

export async function handleToken(c: AppContext): Promise<Response> {
  const publicRateLimitResponse = await enforceRateLimit(
    c,
    c.env.PUBLIC_RATE_LIMITER,
    `token:ip:${getClientIp(c)}`,
    { route: '/token', scope: 'ip' },
  )

  if (publicRateLimitResponse !== null) {
    return publicRateLimitResponse
  }

  const config = await loadAuthServerConfig(c.env)
  const occurredAt = Math.floor(Date.now() / 1000)

  const contentType = c.req.header('Content-Type')
  const mediaType = contentType?.split(';', 1)[0]?.trim().toLowerCase()

  if (mediaType !== 'application/x-www-form-urlencoded') {
    return tokenError(c, 'invalid_request')
  }

  let form: FormData

  try {
    form = await c.req.formData()
  } catch {
    return tokenError(c, 'invalid_request')
  }

  const grantType = getSingleFormValue(form, 'grant_type')

  if (!grantType) {
    return tokenError(c, 'invalid_request')
  }

  if (grantType === 'authorization_code') {
    return handleAuthorizationCodeGrant(c, config, occurredAt, form)
  }

  if (grantType === 'refresh_token') {
    return handleRefreshTokenGrant(c, config, occurredAt, form)
  }

  return tokenError(c, 'unsupported_grant_type')
}
