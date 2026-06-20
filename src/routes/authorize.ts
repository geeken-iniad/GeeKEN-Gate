import type { Context } from 'hono'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import { generateRandomToken, hashAuthToken } from '../lib/crypto'
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

function getSingleQueryValue(
  searchParams: URLSearchParams,
  name: string,
): string | null {
  const values = searchParams.getAll(name)

  if (values.length !== 1) {
    return null
  }

  return values[0]
}

export async function handleAuthorize(c: AppContext): Promise<Response> {
  const rateLimitResponse = await enforceRateLimit(
    c,
    c.env.PUBLIC_RATE_LIMITER,
    `authorize:ip:${getClientIp(c)}`,
    { route: '/authorize', scope: 'ip' },
  )

  if (rateLimitResponse !== null) {
    return rateLimitResponse
  }

  const searchParams = new URL(c.req.url).searchParams
  const clientId = getSingleQueryValue(searchParams, 'client_id')
  const redirectUri = getSingleQueryValue(searchParams, 'redirect_uri')
  const responseType = getSingleQueryValue(searchParams, 'response_type')
  const scope = getSingleQueryValue(searchParams, 'scope')
  const state = getSingleQueryValue(searchParams, 'state')
  const nonce = getSingleQueryValue(searchParams, 'nonce')
  const codeChallenge = getSingleQueryValue(searchParams, 'code_challenge')
  const codeChallengeMethod = getSingleQueryValue(
    searchParams,
    'code_challenge_method',
  )
  const provider = getSingleQueryValue(searchParams, 'provider') ?? 'github'

  if (
    !clientId ||
    !redirectUri ||
    !responseType ||
    !scope ||
    !state ||
    !nonce ||
    !codeChallenge ||
    !codeChallengeMethod
  ) {
    return c.json({ error: 'invalid_request' }, 400)
  }

  if (responseType !== 'code') {
    return c.json({ error: 'unsupported_response_type' }, 400)
  }

  if (scope !== 'openid') {
    return c.json({ error: 'invalid_scope' }, 400)
  }

  if (codeChallengeMethod !== 'S256') {
    return c.json({ error: 'invalid_request' }, 400)
  }

  if (provider !== 'github') {
    return c.json(
      {
        error: 'invalid_request',
        error_description:
          'Only provider=github is supported in this phase. The provider chooser and Google login are planned for a later phase.',
      },
      400,
    )
  }

  const config = await loadAuthServerConfig(c.env)
  const isAllowed = await isAllowedClientRedirect(
    config.db,
    clientId,
    redirectUri,
  )

  if (!isAllowed) {
    return c.json({ error: 'invalid_request' }, 400)
  }

  const upstreamState = generateRandomToken()
  const upstreamStateHash = await hashAuthToken(
    upstreamState,
    config.tokenHashSecret,
    'oauth-upstream-state',
  )
  const createdAt = Math.floor(Date.now() / 1000)

  await config.db
    .prepare(
      `INSERT INTO oauth_states
         (upstream_state_hash, client_state, client_id, redirect_uri, nonce,
          code_challenge, code_challenge_method, provider, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      upstreamStateHash,
      state,
      clientId,
      redirectUri,
      nonce,
      codeChallenge,
      codeChallengeMethod,
      provider,
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
