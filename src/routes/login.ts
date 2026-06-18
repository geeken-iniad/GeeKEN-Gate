import type { Context } from 'hono'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import { generateRandomToken, hashAuthToken } from '../lib/crypto'
import { HTTP_STATUS } from '../lib/http-status'
import { enforceRateLimit, getClientIp } from '../lib/rate-limit'

const GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
const OAUTH_STATE_LIFETIME_SECONDS = 10 * 60

type AppContext = Context<{ Bindings: AppBindings }>

async function isAllowedClientRedirect(
  database: D1Database,
  clientId: string,
  redirectUri: string,
): Promise<boolean> {
  const clientRedirect = await database
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

  return clientRedirect !== null
}

export async function handleLogin(c: AppContext): Promise<Response> {
  const rateLimitResponse = await enforceRateLimit(
    c,
    c.env.PUBLIC_RATE_LIMITER,
    `login:ip:${getClientIp(c)}`,
    { route: '/login', scope: 'ip' },
  )

  if (rateLimitResponse !== null) {
    return rateLimitResponse
  }

  const clientId = c.req.query('client_id')
  const redirectUri = c.req.query('redirect_uri')

  if (!clientId || !redirectUri) {
    return c.json({ error: 'invalid_request' }, HTTP_STATUS.BAD_REQUEST)
  }

  const config = loadAuthServerConfig(c.env)
  const isAllowed = await isAllowedClientRedirect(
    config.db,
    clientId,
    redirectUri,
  )

  if (!isAllowed) {
    return c.json({ error: 'invalid_request' }, HTTP_STATUS.BAD_REQUEST)
  }

  const state = generateRandomToken()
  const stateHash = await hashAuthToken(
    state,
    config.sessionSecret,
    'oauth-state',
  )
  const createdAt = Math.floor(Date.now() / 1000)

  await config.db
    .prepare(
      `INSERT INTO oauth_states
         (state_hash, client_id, redirect_uri, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .bind(
      stateHash,
      clientId,
      redirectUri,
      createdAt,
      createdAt + OAUTH_STATE_LIFETIME_SECONDS,
    )
    .run()

  const authorizeUrl = new URL(GITHUB_AUTHORIZE_URL)
  authorizeUrl.searchParams.set('client_id', config.githubClientId)
  authorizeUrl.searchParams.set('redirect_uri', config.githubCallbackUrl.href)
  authorizeUrl.searchParams.set('scope', 'read:org')
  authorizeUrl.searchParams.set('state', state)

  c.header('Cache-Control', 'no-store')

  return c.redirect(authorizeUrl.href)
}
