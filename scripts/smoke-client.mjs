import http from 'node:http'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const DEFAULT_PORT = 3000
const DEFAULT_PROVIDER = 'github'
const CLOCK_SKEW_SECONDS = 60
const REQUIRED_ENVIRONMENT_VARIABLES = [
  'GATE_BASE_URL',
  'SMOKE_CLIENT_ID',
  'SMOKE_CLIENT_SECRET',
  'SMOKE_REDIRECT_URI',
]

const textEncoder = new TextEncoder()

function base64UrlEncode(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '')
}

function base64UrlDecode(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/')
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '=')
  return Buffer.from(padded, 'base64')
}

function base64UrlJson(value) {
  return JSON.parse(base64UrlDecode(value).toString('utf8'))
}

async function sha256(value) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', textEncoder.encode(value)))
}

function randomBase64Url(byteLength = 32) {
  const bytes = new Uint8Array(byteLength)
  crypto.getRandomValues(bytes)
  return base64UrlEncode(bytes)
}

function parseUrl(name, value) {
  try {
    return new URL(value)
  } catch {
    throw new Error(`${name} must be an absolute URL`)
  }
}

function parseBoolean(value, defaultValue) {
  if (value === undefined) return defaultValue
  if (/^(1|true|yes)$/i.test(value)) return true
  if (/^(0|false|no)$/i.test(value)) return false
  throw new Error('SMOKE_USERINFO must be true or false')
}

export function loadConfig(environment = process.env) {
  for (const name of REQUIRED_ENVIRONMENT_VARIABLES) {
    if (!environment[name]) {
      throw new Error(`Missing required environment variable: ${name}`)
    }
  }

  const portValue = environment.SMOKE_PORT ?? String(DEFAULT_PORT)
  const port = Number(portValue)

  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error('SMOKE_PORT must be an integer between 1 and 65535')
  }

  const provider = environment.SMOKE_PROVIDER ?? DEFAULT_PROVIDER
  if (provider !== 'github' && provider !== 'google') {
    throw new Error('SMOKE_PROVIDER must be github or google')
  }

  const gateBaseUrl = parseUrl('GATE_BASE_URL', environment.GATE_BASE_URL)
  const redirectUri = parseUrl(
    'SMOKE_REDIRECT_URI',
    environment.SMOKE_REDIRECT_URI,
  )

  if (
    !['http:', 'https:'].includes(gateBaseUrl.protocol) ||
    gateBaseUrl.username ||
    gateBaseUrl.password ||
    gateBaseUrl.search ||
    gateBaseUrl.hash
  ) {
    throw new Error(
      'GATE_BASE_URL must be an HTTP(S) URL without credentials, query, or fragment',
    )
  }

  if (
    redirectUri.protocol !== 'http:' ||
    redirectUri.hostname !== 'localhost' ||
    redirectUri.port !== String(port) ||
    redirectUri.pathname !== '/callback' ||
    redirectUri.search ||
    redirectUri.hash
  ) {
    throw new Error(
      'SMOKE_REDIRECT_URI must be http://localhost:<SMOKE_PORT>/callback',
    )
  }

  return {
    gateBaseUrl: new URL(gateBaseUrl.href.replace(/\/+$/, '') + '/'),
    clientId: environment.SMOKE_CLIENT_ID,
    clientSecret: environment.SMOKE_CLIENT_SECRET,
    redirectUri: redirectUri.href,
    port,
    provider,
    callUserinfo: parseBoolean(environment.SMOKE_USERINFO, true),
  }
}

export function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function redact(value, secrets) {
  let redacted = value

  for (const secret of secrets) {
    if (secret) {
      redacted = redacted.replaceAll(secret, '[REDACTED]')
    }
  }

  return redacted
}

function formatBody(body, secrets) {
  const formatted =
    typeof body === 'string' ? body : JSON.stringify(body, null, 2)

  return escapeHtml(redact(formatted, secrets))
}

function page(title, content) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    body { font-family: sans-serif; max-width: 820px; margin: 40px auto; padding: 0 20px; line-height: 1.5; }
    .ok { color: #087830; }
    .error { color: #b42318; }
    pre { background: #f4f4f4; padding: 12px; overflow-wrap: anywhere; white-space: pre-wrap; }
  </style>
</head>
<body>
  <h1>${escapeHtml(title)}</h1>
  ${content}
</body>
</html>`
}

function writeHtml(response, status, body) {
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'",
    'Content-Type': 'text/html; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
  })
  response.end(body)
}

function writeRedirect(response, location) {
  response.writeHead(302, {
    'Cache-Control': 'no-store',
    Location: location,
  })
  response.end()
}

function requireMetadataUrl(discovery, property) {
  if (typeof discovery[property] !== 'string') {
    throw new Error(`Discovery document is missing ${property}`)
  }
  return discovery[property]
}

export async function fetchDiscovery(config, fetchImplementation = fetch) {
  const discoveryUrl = new URL('.well-known/openid-configuration', config.gateBaseUrl)
  const response = await fetchImplementation(discoveryUrl)
  if (!response.ok) throw new Error(`Discovery request failed with ${response.status}`)
  const discovery = await response.json()
  const issuer = config.gateBaseUrl.href.replace(/\/$/, '')

  if (discovery.issuer !== issuer) {
    throw new Error('Discovery issuer does not match GATE_BASE_URL')
  }

  for (const property of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
    requireMetadataUrl(discovery, property)
  }

  return discovery
}

export async function createPkce() {
  const codeVerifier = randomBase64Url(32)
  const codeChallenge = base64UrlEncode(await sha256(codeVerifier))
  return { codeVerifier, codeChallenge, codeChallengeMethod: 'S256' }
}

export async function createAuthorizationRequest(config, discovery) {
  const pkce = await createPkce()
  const state = crypto.randomUUID()
  const nonce = crypto.randomUUID()
  const transaction = {
    state,
    nonce,
    provider: config.provider,
    ...pkce,
  }
  return {
    ...transaction,
    authorizationUrl: buildAuthorizeUrl(config, discovery, transaction),
  }
}

export function buildAuthorizeUrl(config, discovery, transaction = {}) {
  const state = transaction.state ?? crypto.randomUUID()
  const nonce = transaction.nonce ?? crypto.randomUUID()
  const provider = transaction.provider ?? config.provider ?? DEFAULT_PROVIDER
  const codeChallenge = transaction.codeChallenge
  const codeChallengeMethod = transaction.codeChallengeMethod ?? (codeChallenge ? 'S256' : undefined)
  const authorizeUrl = new URL(requireMetadataUrl(discovery, 'authorization_endpoint'))
  authorizeUrl.searchParams.set('response_type', 'code')
  authorizeUrl.searchParams.set('client_id', config.clientId)
  authorizeUrl.searchParams.set('redirect_uri', config.redirectUri)
  authorizeUrl.searchParams.set('scope', 'openid')
  authorizeUrl.searchParams.set('state', state)
  authorizeUrl.searchParams.set('nonce', nonce)
  authorizeUrl.searchParams.set('provider', provider)
  if (codeChallenge) {
    authorizeUrl.searchParams.set('code_challenge', codeChallenge)
    authorizeUrl.searchParams.set('code_challenge_method', codeChallengeMethod)
  }

  return authorizeUrl.href
}

export async function exchangeCode(config, discovery, code, codeVerifier, fetchImplementation = fetch) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    code_verifier: codeVerifier,
  })
  const authorization = Buffer.from(
    `${config.clientId}:${config.clientSecret}`,
    'utf8',
  ).toString('base64')
  const response = await fetchImplementation(
    new URL(requireMetadataUrl(discovery, 'token_endpoint')),
    {
      method: 'POST',
      headers: {
        Authorization: `Basic ${authorization}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    },
  )
  const text = await response.text()
  let responseBody = text

  try {
    responseBody = JSON.parse(text)
  } catch {
    // Keep non-JSON error bodies readable in the smoke-test output.
  }

  return {
    status: response.status,
    ok: response.ok,
    body: responseBody,
  }
}

export async function fetchJwks(discovery, fetchImplementation = fetch) {
  const response = await fetchImplementation(new URL(requireMetadataUrl(discovery, 'jwks_uri')))
  if (!response.ok) throw new Error(`JWKS request failed with ${response.status}`)
  const jwks = await response.json()
  if (!Array.isArray(jwks.keys)) throw new Error('JWKS did not contain keys')
  return jwks
}

function jwkAlgorithm(jwk, header) {
  const alg = header.alg ?? jwk.alg
  if (alg === 'ES256') return { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }
  if (alg === 'RS256') return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
  throw new Error(`Unsupported ID Token alg: ${alg}`)
}

function verifyClaims(claims, expected, now = Math.floor(Date.now() / 1000)) {
  if (claims.iss !== expected.issuer) throw new Error('ID Token iss claim is invalid')
  if (claims.aud !== expected.clientId) throw new Error('ID Token aud claim is invalid')
  if (typeof claims.exp !== 'number' || claims.exp <= now - CLOCK_SKEW_SECONDS) throw new Error('ID Token exp claim is invalid')
  if (typeof claims.iat !== 'number' || claims.iat > now + CLOCK_SKEW_SECONDS) throw new Error('ID Token iat claim is invalid')
  if (typeof claims.auth_time !== 'number' || claims.auth_time > now + CLOCK_SKEW_SECONDS) throw new Error('ID Token auth_time claim is invalid')
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) throw new Error('ID Token sub claim is missing')
  if (expected.nonce && claims.nonce !== expected.nonce) throw new Error('ID Token nonce claim is invalid')
}

export async function verifyIdToken(idToken, jwks, expected) {
  const parts = idToken.split('.')
  if (parts.length !== 3) throw new Error('ID Token must be a compact JWS')
  const [encodedHeader, encodedClaims, encodedSignature] = parts
  const header = base64UrlJson(encodedHeader)
  const claims = base64UrlJson(encodedClaims)
  const jwk = header.kid
    ? jwks.keys.find((key) => key.kid === header.kid)
    : jwks.keys.find((key) => key.alg === header.alg)
  if (!jwk) throw new Error('No JWKS key matched the ID Token')
  const algorithm = jwkAlgorithm(jwk, header)
  const verifyAlgorithm = header.alg === 'ES256'
    ? { name: 'ECDSA', hash: 'SHA-256' }
    : { name: 'RSASSA-PKCS1-v1_5' }
  const key = await crypto.subtle.importKey('jwk', jwk, algorithm, false, ['verify'])
  const verified = await crypto.subtle.verify(
    verifyAlgorithm,
    key,
    base64UrlDecode(encodedSignature),
    textEncoder.encode(`${encodedHeader}.${encodedClaims}`),
  )
  if (!verified) throw new Error('ID Token signature verification failed')
  verifyClaims(claims, expected)
  return claims
}

export async function fetchUserinfo(discovery, accessToken, fetchImplementation = fetch) {
  if (typeof discovery.userinfo_endpoint !== 'string' || discovery.userinfo_endpoint.length === 0) {
    return {
      status: 0,
      ok: false,
      body: { error: 'Discovery document has no usable userinfo_endpoint' },
    }
  }
  const response = await fetchImplementation(new URL(discovery.userinfo_endpoint), {
    headers: { Authorization: `Bearer ${accessToken}` },
  })
  const text = await response.text()
  let body = text
  try {
    body = JSON.parse(text)
  } catch {
    // Keep non-JSON error bodies readable.
  }
  return { status: response.status, ok: response.ok, body }
}

function renderResult(label, result, secrets) {
  return `<h2>${escapeHtml(label)}</h2>
<p>Status: <strong>${result.status}</strong></p>
<pre>${formatBody(result.body, secrets)}</pre>`
}

function createTransaction(config) {
  const codeVerifier = randomBase64Url(32)
  return {
    state: crypto.randomUUID(),
    nonce: crypto.randomUUID(),
    provider: config.provider,
    codeVerifier,
    codeChallengeMethod: 'S256',
  }
}

export function createRequestHandler(config, dependencies = {}) {
  const getDiscovery = dependencies.fetchDiscovery ?? fetchDiscovery
  const requestExchange = dependencies.exchangeCode ?? exchangeCode
  const requestJwks = dependencies.fetchJwks ?? fetchJwks
  const verifyToken = dependencies.verifyIdToken ?? verifyIdToken
  const requestUserinfo = dependencies.fetchUserinfo ?? fetchUserinfo
  const transactions = dependencies.transactions ?? new Map()

  return async (request, response) => {
    if (request.method !== 'GET') {
      writeHtml(response, 405, page('Method Not Allowed', '<p>Use GET.</p>'))
      return
    }

    const requestUrl = new URL(
      request.url ?? '/',
      `http://${request.headers.host ?? `localhost:${config.port}`}`,
    )

    if (requestUrl.pathname === '/') {
      const providerLinks = ['github', 'google'].map((provider) =>
        `<li><a href="/start?provider=${provider}">Start OIDC login through ${provider}</a></li>`,
      ).join('')
      writeHtml(
        response,
        200,
        page(
          'GeeKEN Gate OIDC Smoke Client',
          `<p>This client discovers GeeKEN Gate, starts Authorization Code + PKCE, verifies the ID Token with JWKS, and displays the GeeKEN Gate <code>sub</code>.</p>
<p>Default provider from <code>SMOKE_PROVIDER</code>: <strong>${escapeHtml(config.provider)}</strong>.</p>
<ul>${providerLinks}</ul>`,
        ),
      )
      return
    }

    if (requestUrl.pathname === '/start') {
      const provider = requestUrl.searchParams.get('provider') ?? config.provider
      if (provider !== 'github' && provider !== 'google') {
        writeHtml(response, 400, page('Invalid Provider', '<p class="error">provider must be github or google.</p>'))
        return
      }
      try {
        const discovery = await getDiscovery(config)
        const transaction = createTransaction({ ...config, provider })
        transaction.codeChallenge = base64UrlEncode(await sha256(transaction.codeVerifier))
        transactions.set(transaction.state, transaction)
        writeRedirect(response, buildAuthorizeUrl({ ...config, provider }, discovery, transaction))
      } catch (error) {
        writeHtml(response, 502, page('Discovery Failed', `<p class="error">${escapeHtml(error instanceof Error ? error.message : String(error))}</p>`))
      }
      return
    }

    if (requestUrl.pathname !== '/callback') {
      writeHtml(response, 404, page('Not Found', '<p>Route not found.</p>'))
      return
    }

    const state = requestUrl.searchParams.get('state')
    const transaction = state ? transactions.get(state) : undefined
    if (!state || !transaction) {
      writeHtml(response, 400, page('OAuth Failed', '<p class="error">The callback state was missing or unknown.</p>'))
      return
    }
    transactions.delete(state)

    const secrets = [config.clientSecret]
    const errors = requestUrl.searchParams.getAll('error')
    if (errors.length > 0) {
      const message = errors.length === 1 && errors[0]
        ? escapeHtml(redact(errors[0], secrets))
        : 'Invalid OAuth error response'
      writeHtml(response, 400, page('OAuth Failed', `<p class="error">${message}</p>`))
      return
    }

    const codes = requestUrl.searchParams.getAll('code')
    if (codes.length !== 1 || !codes[0]) {
      writeHtml(
        response,
        400,
        page('OAuth Failed', '<p class="error">The callback did not contain exactly one authorization code.</p>'),
      )
      return
    }
    const code = codes[0]
    secrets.push(code)

    try {
      const discovery = await getDiscovery(config)
      const issuer = discovery.issuer
      const exchange = await requestExchange(config, discovery, code, transaction.codeVerifier)
      secrets.push(exchange.body?.access_token, exchange.body?.id_token)
      if (!exchange.ok || typeof exchange.body !== 'object' || typeof exchange.body.id_token !== 'string') {
        writeHtml(response, 502, page('OIDC Smoke Test Result', `<p class="error"><strong>Token exchange failed.</strong></p>${renderResult('Token response', exchange, secrets)}`))
        return
      }
      if (config.callUserinfo && typeof exchange.body.access_token !== 'string') {
        writeHtml(response, 502, page('OIDC Smoke Test Result', `<p class="error"><strong>Token response did not contain a usable access token for UserInfo verification.</strong></p>${renderResult('Token response', exchange, secrets)}`))
        return
      }

      const jwks = await requestJwks(discovery)
      const claims = await verifyToken(exchange.body.id_token, jwks, {
        issuer,
        clientId: config.clientId,
        nonce: transaction.nonce,
      })
      let userinfoHtml = '<p>UserInfo skipped.</p>'
      if (config.callUserinfo) {
        const userinfo = await requestUserinfo(discovery, exchange.body.access_token)
        secrets.push(exchange.body.access_token)
        if (userinfo.skipped) {
          userinfoHtml = `<p>UserInfo skipped: ${escapeHtml(userinfo.reason)}</p>`
        } else if (userinfo.ok && userinfo.body?.sub === claims.sub) {
          userinfoHtml = `<p class="ok"><strong>UserInfo sub:</strong> <code>${escapeHtml(userinfo.body.sub)}</code></p>`
        } else if (userinfo.ok) {
          userinfoHtml = `<p class="error"><strong>UserInfo sub did not match the ID Token sub.</strong></p>${renderResult('UserInfo response', userinfo, secrets)}`
          writeHtml(
            response,
            502,
            page('OIDC Smoke Test Result', `<p class="error"><strong>UserInfo verification failed.</strong></p>${userinfoHtml}`),
          )
          return
        } else {
          userinfoHtml = `<p class="error"><strong>UserInfo request failed.</strong></p>${renderResult('UserInfo response', userinfo, secrets)}`
          writeHtml(
            response,
            502,
            page('OIDC Smoke Test Result', `<p class="error"><strong>UserInfo verification failed.</strong></p>${userinfoHtml}`),
          )
          return
        }
      }

      writeHtml(
        response,
        200,
        page(
          'OIDC Smoke Test Result',
          `<p class="ok"><strong>Token exchange and ID Token verification succeeded.</strong></p>
<p><strong>GeeKEN Gate sub:</strong> <code>${escapeHtml(claims.sub)}</code></p>
<p><strong>Issuer:</strong> <code>${escapeHtml(claims.iss)}</code></p>
${userinfoHtml}`,
        ),
      )
    } catch (error) {
      writeHtml(
        response,
        502,
        page('OIDC Smoke Test Result', `<p class="error">${escapeHtml(error instanceof Error ? error.message : String(error))}</p>`),
      )
    }
  }
}

export function startSmokeClient(
  environment = process.env,
  dependencies = {},
) {
  const config = loadConfig(environment)
  const createServer = dependencies.createServer ?? http.createServer
  const server = createServer(createRequestHandler(config, dependencies))

  server.listen(config.port, 'localhost', () => {
    console.log(`OIDC smoke client listening on http://localhost:${config.port}`)
    console.log(`Default provider: ${config.provider}. Override with SMOKE_PROVIDER=github|google.`)
  })

  return server
}

function main() {
  try {
    startSmokeClient()
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error))
    process.exitCode = 1
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  main()
}
