import type { Context } from 'hono'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import { generateRandomToken, hashAuthToken } from '../lib/crypto'
import { getUserAdmission } from '../lib/identity'
import { publicJwkFromPrivate, signIdToken, verifyPkceChallenge } from '../lib/oidc'
import { enforceRateLimit, getClientIp } from '../lib/rate-limit'

const GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
const OAUTH_STATE_LIFETIME_SECONDS = 10 * 60
const ACCESS_TOKEN_LIFETIME_SECONDS = 60 * 60
const ID_TOKEN_LIFETIME_SECONDS = 5 * 60
const BASIC_AUTH_PATTERN = /^Basic ([A-Za-z0-9+/]+={0,2})$/i
const DUMMY_CLIENT_SECRET_HASH = '0'.repeat(64)

type AppContext = Context<{ Bindings: AppBindings }>

interface ClientRow { client_secret_hash: string }
interface AuthCodeRow {
  user_id: string
  scope: string | null
  nonce: string | null
  provider: string | null
  auth_time: number | null
  code_challenge: string | null
  code_challenge_method: string | null
}

function includesScope(scope: string | null, required: string): boolean {
  return scope?.split(/\s+/).includes(required) ?? false
}

function isValidPkceChallenge(challenge: string): boolean {
  return /^[A-Za-z0-9_-]{43,128}$/.test(challenge)
}

function endpoint(c: AppContext, path: string): string {
  const config = loadAuthServerConfig(c.env)
  return new URL(path, config.oidcIssuer).href
}

function oidcError(c: AppContext, error: string, status: 400 | 401 | 403 = 400, challenge = 'Basic realm="token"'): Response {
  c.header('Cache-Control', 'no-store')
  if (status === 401) c.header('WWW-Authenticate', challenge)
  return c.json({ error }, status)
}

async function validatedClientRedirect(database: D1Database, clientId: string, redirectUri: string) {
  return await database
    .prepare(
      `SELECT 1
       FROM clients
       INNER JOIN allowed_redirect_uris
         ON allowed_redirect_uris.client_id = clients.client_id
       WHERE clients.client_id = ?
         AND clients.disabled_at IS NULL
         AND allowed_redirect_uris.redirect_uri = ?
       LIMIT 1`,
    )
    .bind(clientId, redirectUri)
    .first()
}

function redirectError(redirectUri: string, error: string, state?: string): Response {
  const url = new URL(redirectUri)
  url.searchParams.set('error', error)
  if (state) url.searchParams.set('state', state)
  return new Response(null, {
    status: 302,
    headers: { 'Cache-Control': 'no-store', Location: url.href },
  })
}

export async function handleDiscovery(c: AppContext): Promise<Response> {
  const config = loadAuthServerConfig(c.env)
  return c.json({
    issuer: config.oidcIssuer.href.replace(/\/$/, ''),
    authorization_endpoint: endpoint(c, '/authorize'),
    token_endpoint: endpoint(c, '/token'),
    jwks_uri: endpoint(c, '/jwks.json'),
    userinfo_endpoint: endpoint(c, '/userinfo'),
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['ES256'],
    scopes_supported: ['openid'],
    token_endpoint_auth_methods_supported: ['client_secret_basic'],
    claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce'],
    code_challenge_methods_supported: ['S256'],
  })
}

export async function handleJwks(c: AppContext): Promise<Response> {
  const config = loadAuthServerConfig(c.env)
  return c.json({ keys: [publicJwkFromPrivate(config.oidcPrivateJwk)] })
}

export async function handleAuthorize(c: AppContext): Promise<Response> {
  const rateLimitResponse = await enforceRateLimit(
    c,
    c.env.PUBLIC_RATE_LIMITER,
    `authorize:ip:${getClientIp(c)}`,
    { route: '/authorize', scope: 'ip' },
  )
  if (rateLimitResponse !== null) return rateLimitResponse

  const config = loadAuthServerConfig(c.env)
  const responseType = c.req.query('response_type')
  const clientId = c.req.query('client_id')
  const redirectUri = c.req.query('redirect_uri')
  const scope = c.req.query('scope')
  const state = c.req.query('state')
  const nonce = c.req.query('nonce')
  const provider = c.req.query('provider')
  const codeChallenge = c.req.query('code_challenge')
  const codeChallengeMethod = c.req.query('code_challenge_method')

  if (!clientId || !redirectUri) return oidcError(c, 'invalid_request')
  const safeRedirect = await validatedClientRedirect(config.db, clientId, redirectUri)
  if (safeRedirect === null) return oidcError(c, 'invalid_request')

  const invalid =
    responseType !== 'code' ||
    !includesScope(scope ?? null, 'openid') ||
    !state ||
    !nonce ||
    !provider ||
    provider !== 'github' ||
    (codeChallengeMethod !== undefined && codeChallengeMethod !== 'S256') ||
    (codeChallenge !== undefined && (!codeChallenge || !isValidPkceChallenge(codeChallenge))) ||
    (codeChallenge === undefined && codeChallengeMethod !== undefined)

  if (invalid) return redirectError(redirectUri, provider === 'google' ? 'temporarily_unavailable' : 'invalid_request', state)

  const upstreamState = generateRandomToken()
  const stateHash = await hashAuthToken(upstreamState, config.sessionSecret, 'oauth-state')
  const createdAt = Math.floor(Date.now() / 1000)

  await config.db
    .prepare(
      `INSERT INTO oauth_states
         (state_hash, client_id, redirect_uri, client_state, scope, nonce, provider,
          code_challenge, code_challenge_method, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      stateHash,
      clientId,
      redirectUri,
      state,
      scope,
      nonce,
      provider,
      codeChallenge ?? null,
      codeChallenge ? 'S256' : null,
      createdAt,
      createdAt + OAUTH_STATE_LIFETIME_SECONDS,
    )
    .run()

  const authorizeUrl = new URL(GITHUB_AUTHORIZE_URL)
  authorizeUrl.searchParams.set('client_id', config.githubClientId)
  authorizeUrl.searchParams.set('redirect_uri', config.githubCallbackUrl.href)
  authorizeUrl.searchParams.set('scope', 'read:org')
  authorizeUrl.searchParams.set('state', upstreamState)
  c.header('Cache-Control', 'no-store')
  return c.redirect(authorizeUrl.href)
}

function parseBasic(authorization: string | undefined) {
  const encoded = authorization?.match(BASIC_AUTH_PATTERN)?.[1]
  if (!encoded) return null
  let decoded: string
  try { decoded = atob(encoded) } catch { return null }
  const separator = decoded.indexOf(':')
  if (separator <= 0 || separator === decoded.length - 1) return null
  return { clientId: decoded.slice(0, separator), clientSecret: decoded.slice(separator + 1) }
}

async function verifyClient(c: AppContext, clientId: string, clientSecret: string) {
  const { verifyClientSecret } = await import('../lib/crypto')
  const config = loadAuthServerConfig(c.env)
  const client = await config.db.prepare(
    `SELECT client_secret_hash FROM clients WHERE client_id = ? AND disabled_at IS NULL LIMIT 1`,
  ).bind(clientId).first<ClientRow>()
  const matches = await verifyClientSecret(clientSecret, client?.client_secret_hash ?? DUMMY_CLIENT_SECRET_HASH)
  return client !== null && matches
}

export async function handleToken(c: AppContext): Promise<Response> {
  const config = loadAuthServerConfig(c.env)
  const ipRateLimitResponse = await enforceRateLimit(
    c,
    c.env.PUBLIC_RATE_LIMITER,
    `token:ip:${getClientIp(c)}`,
    { route: '/token', scope: 'ip' },
  )
  if (ipRateLimitResponse !== null) return ipRateLimitResponse

  const credentials = parseBasic(c.req.header('Authorization'))
  if (credentials === null || !(await verifyClient(c, credentials.clientId, credentials.clientSecret))) {
    return oidcError(c, 'invalid_client', 401)
  }
  const clientRateLimitResponse = await enforceRateLimit(
    c,
    c.env.CLIENT_RATE_LIMITER,
    `token:client:${credentials.clientId}`,
    { route: '/token', scope: 'client', clientId: credentials.clientId },
  )
  if (clientRateLimitResponse !== null) return clientRateLimitResponse

  const contentType = c.req.header('Content-Type')
  if (contentType?.split(';', 1)[0]?.trim().toLowerCase() !== 'application/x-www-form-urlencoded') {
    return oidcError(c, 'invalid_request')
  }
  const form = await c.req.formData()
  const grantType = form.get('grant_type')
  const code = form.get('code')
  const redirectUri = form.get('redirect_uri')
  const codeVerifier = form.get('code_verifier')
  if (grantType !== 'authorization_code' || typeof code !== 'string' || typeof redirectUri !== 'string') {
    return oidcError(c, 'invalid_request')
  }
  const now = Math.floor(Date.now() / 1000)
  const codeHash = await hashAuthToken(code, config.sessionSecret, 'auth-code')
  const authCode = await config.db.prepare(
    `DELETE FROM auth_codes
     WHERE code_hash = ? AND client_id = ? AND redirect_uri = ? AND expires_at > ?
     RETURNING user_id, scope, nonce, provider, auth_time, code_challenge, code_challenge_method`,
  ).bind(codeHash, credentials.clientId, redirectUri, now).first<AuthCodeRow>()
  if (authCode === null) return oidcError(c, 'invalid_grant')
  if (
    !includesScope(authCode.scope, 'openid') ||
    !authCode.nonce ||
    authCode.provider !== 'github' ||
    authCode.auth_time === null ||
    authCode.auth_time <= 0 ||
    (authCode.code_challenge === null && authCode.code_challenge_method !== null) ||
    (authCode.code_challenge !== null && (authCode.code_challenge_method !== 'S256' || !isValidPkceChallenge(authCode.code_challenge)))
  ) {
    return oidcError(c, 'invalid_grant')
  }
  if (authCode.code_challenge !== null) {
    const codeChallengeMethod = authCode.code_challenge_method
    if (codeChallengeMethod !== 'S256' || typeof codeVerifier !== 'string' || !(await verifyPkceChallenge(codeVerifier, authCode.code_challenge, codeChallengeMethod))) {
      return oidcError(c, 'invalid_grant')
    }
  }
  const admission = await getUserAdmission(config.db, authCode.user_id)
  if (!admission.allowed) return oidcError(c, 'access_denied', 403)

  const accessToken = generateRandomToken()
  const accessTokenHash = await hashAuthToken(accessToken, config.sessionSecret, 'access-token')
  await config.db.prepare(
    `INSERT INTO access_tokens (token_hash, user_id, client_id, scope, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).bind(accessTokenHash, authCode.user_id, credentials.clientId, authCode.scope, now, now + ACCESS_TOKEN_LIFETIME_SECONDS).run()
  const issuer = config.oidcIssuer.href.replace(/\/$/, '')
  const idToken = await signIdToken({
    iss: issuer,
    sub: authCode.user_id,
    aud: credentials.clientId,
    iat: now,
    exp: now + ID_TOKEN_LIFETIME_SECONDS,
    auth_time: authCode.auth_time,
    nonce: authCode.nonce,
  }, config.oidcPrivateJwk)
  c.header('Cache-Control', 'no-store')
  return c.json({ access_token: accessToken, token_type: 'Bearer', expires_in: ACCESS_TOKEN_LIFETIME_SECONDS, id_token: idToken })
}

export async function handleUserinfo(c: AppContext): Promise<Response> {
  const config = loadAuthServerConfig(c.env)
  const authorization = c.req.header('Authorization')
  const token = authorization?.match(/^Bearer (\S+)$/i)?.[1]
  if (!token) return oidcError(c, 'invalid_token', 401, 'Bearer realm="userinfo"')
  const now = Math.floor(Date.now() / 1000)
  const tokenHash = await hashAuthToken(token, config.sessionSecret, 'access-token')
  const row = await config.db.prepare(
    `SELECT access_tokens.user_id
     FROM access_tokens
     INNER JOIN clients ON clients.client_id = access_tokens.client_id
     WHERE access_tokens.token_hash = ?
       AND access_tokens.expires_at > ?
       AND clients.disabled_at IS NULL
     LIMIT 1`,
  ).bind(tokenHash, now).first<{ user_id: string }>()
  if (row === null) return oidcError(c, 'invalid_token', 401, 'Bearer realm="userinfo"')
  const admission = await getUserAdmission(config.db, row.user_id)
  if (!admission.allowed) return oidcError(c, 'invalid_token', 401, 'Bearer realm="userinfo"')
  c.header('Cache-Control', 'no-store')
  return c.json({ sub: row.user_id })
}
