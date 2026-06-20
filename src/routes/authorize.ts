import type { Context } from 'hono'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import { generateRandomToken, hashAuthToken } from '../lib/crypto'
import { enforceRateLimit, getClientIp } from '../lib/rate-limit'

const GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
const OAUTH_STATE_LIFETIME_SECONDS = 10 * 60

type AppContext = Context<{ Bindings: AppBindings }>

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

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

function getOptionalSingleQueryValue(
  searchParams: URLSearchParams,
  name: string,
): { ok: true; value: string | null } | { ok: false } {
  const values = searchParams.getAll(name)

  if (values.length === 0) {
    return { ok: true, value: null }
  }

  if (values.length === 1) {
    return { ok: true, value: values[0] ?? '' }
  }

  return { ok: false }
}

interface AuthorizeParams {
  clientId: string
  redirectUri: string
  responseType: string
  scope: string
  state: string
  nonce: string
  codeChallenge: string
  codeChallengeMethod: string
}

function parseAuthorizeParams(
  searchParams: URLSearchParams,
): AuthorizeParams | null {
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
    return null
  }

  return {
    clientId,
    redirectUri,
    responseType,
    scope,
    state,
    nonce,
    codeChallenge,
    codeChallengeMethod,
  }
}

function validateAuthorizeParams(params: AuthorizeParams): boolean {
  if (params.responseType !== 'code') {
    return false
  }

  if (params.scope !== 'openid') {
    return false
  }

  if (params.codeChallengeMethod !== 'S256') {
    return false
  }

  return true
}

function providerSelectionUrl(
  requestUrl: URL,
  provider: 'github' | 'google',
): URL {
  const url = new URL(requestUrl)
  url.searchParams.set('provider', provider)

  return url
}

function renderProviderSelection(c: AppContext, params: AuthorizeParams): Response {
  const requestUrl = new URL(c.req.url)
  const githubUrl = providerSelectionUrl(requestUrl, 'github')
  const googleUrl = providerSelectionUrl(requestUrl, 'google')

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in - GeeKEN Gate</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 360px; margin: 60px auto; padding: 0 20px; }
    h1 { font-size: 1.25rem; margin-bottom: 1.5rem; }
    a.button { display: block; padding: 12px 16px; margin-bottom: 12px; text-align: center; text-decoration: none; border-radius: 6px; border: 1px solid #ccc; color: #111; background: #f7f7f7; }
    a.button:hover { background: #eee; }
  </style>
</head>
<body>
  <h1>Choose a sign-in method</h1>
  <a class="button" href="${escapeHtml(githubUrl.href)}">Continue with GitHub</a>
  <a class="button" href="${escapeHtml(googleUrl.href)}">Continue with Google</a>
</body>
</html>`

  c.header('Cache-Control', 'no-store')

  return c.html(html)
}

function renderProviderUnavailable(
  c: AppContext,
  params: AuthorizeParams,
): Response {
  const requestUrl = new URL(c.req.url)
  requestUrl.searchParams.set('provider', 'github')

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in unavailable - GeeKEN Gate</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 360px; margin: 60px auto; padding: 0 20px; }
    p { margin-bottom: 1rem; }
    a { color: #0969da; }
  </style>
</head>
<body>
  <p>Google sign-in is not available in this phase.</p>
  <p><a href="${escapeHtml(requestUrl.href)}">Continue with GitHub</a></p>
</body>
</html>`

  c.header('Cache-Control', 'no-store')

  return c.html(html, 400)
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
  const params = parseAuthorizeParams(searchParams)

  if (params === null) {
    return c.json({ error: 'invalid_request' }, 400)
  }

  if (!validateAuthorizeParams(params)) {
    return c.json({ error: 'invalid_request' }, 400)
  }

  const providerResult = getOptionalSingleQueryValue(searchParams, 'provider')

  if (!providerResult.ok) {
    return c.json({ error: 'invalid_request' }, 400)
  }

  const provider = providerResult.value

  if (provider !== null && provider !== 'github' && provider !== 'google') {
    return c.json({ error: 'invalid_request' }, 400)
  }

  const config = await loadAuthServerConfig(c.env)
  const isAllowed = await isAllowedClientRedirect(
    config.db,
    params.clientId,
    params.redirectUri,
  )

  if (!isAllowed) {
    return c.json({ error: 'invalid_request' }, 400)
  }

  if (provider === null) {
    return renderProviderSelection(c, params)
  }

  if (provider === 'google') {
    return renderProviderUnavailable(c, params)
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
      params.state,
      params.clientId,
      params.redirectUri,
      params.nonce,
      params.codeChallenge,
      params.codeChallengeMethod,
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
