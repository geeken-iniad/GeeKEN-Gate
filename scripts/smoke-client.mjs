import { createHash, randomBytes } from 'node:crypto'
import http from 'node:http'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const DEFAULT_PORT = 3000
const REQUIRED_ENVIRONMENT_VARIABLES = [
  'GATE_BASE_URL',
  'SMOKE_CLIENT_ID',
  'SMOKE_REDIRECT_URI',
]
const SUPPORTED_PROVIDERS = new Set(['github', 'google'])

function parseUrl(name, value) {
  try {
    return new URL(value)
  } catch {
    throw new Error(`${name} must be an absolute URL`)
  }
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

  const provider = environment.SMOKE_PROVIDER ?? 'github'

  if (!SUPPORTED_PROVIDERS.has(provider)) {
    throw new Error('SMOKE_PROVIDER must be "github" or "google"')
  }

  return {
    gateBaseUrl: new URL(gateBaseUrl.href.replace(/\/+$/, '') + '/'),
    clientId: environment.SMOKE_CLIENT_ID,
    redirectUri: redirectUri.href,
    port,
    provider,
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

function base64Url(bytes) {
  return bytes.toString('base64url').replace(/=+$/, '')
}

export function generatePKCE() {
  const verifier = base64Url(randomBytes(32))
  const challenge = base64Url(createHash('sha256').update(verifier).digest())
  const state = base64Url(randomBytes(32))
  const nonce = base64Url(randomBytes(32))

  return { verifier, challenge, state, nonce }
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
    body { font-family: sans-serif; max-width: 760px; margin: 40px auto; padding: 0 20px; line-height: 1.5; }
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

export function buildAuthorizeUrl(config, pkce) {
  const authorizeUrl = new URL('authorize', config.gateBaseUrl)
  authorizeUrl.searchParams.set('client_id', config.clientId)
  authorizeUrl.searchParams.set('redirect_uri', config.redirectUri)
  authorizeUrl.searchParams.set('response_type', 'code')
  authorizeUrl.searchParams.set('scope', 'openid')
  authorizeUrl.searchParams.set('state', pkce.state)
  authorizeUrl.searchParams.set('nonce', pkce.nonce)
  authorizeUrl.searchParams.set('code_challenge', pkce.challenge)
  authorizeUrl.searchParams.set('code_challenge_method', 'S256')
  authorizeUrl.searchParams.set('provider', config.provider)

  return authorizeUrl.href
}

export async function exchangeCode(
  config,
  code,
  verifier,
  fetchImplementation = fetch,
) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    code,
    code_verifier: verifier,
  })
  const response = await fetchImplementation(
    new URL('token', config.gateBaseUrl),
    {
      method: 'POST',
      headers: {
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

export async function fetchUserinfo(
  config,
  accessToken,
  fetchImplementation = fetch,
) {
  const response = await fetchImplementation(
    new URL('userinfo', config.gateBaseUrl),
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  )
  const text = await response.text()
  let responseBody = text

  try {
    responseBody = JSON.parse(text)
  } catch {
    // Keep non-JSON error bodies readable.
  }

  return {
    status: response.status,
    ok: response.ok,
    body: responseBody,
  }
}

function renderResult(label, result, secrets) {
  return `<h2>${escapeHtml(label)}</h2>
<p>Status: <strong>${result.status}</strong></p>
<pre>${formatBody(result.body, secrets)}</pre>`
}

export function createRequestHandler(config, dependencies = {}) {
  const createPkce = dependencies.generatePKCE ?? generatePKCE
  const requestExchange = dependencies.exchangeCode ?? exchangeCode
  const requestUserinfo = dependencies.fetchUserinfo ?? fetchUserinfo
  const pkceStore = dependencies.pkceStore ?? new Map()

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
      writeHtml(
        response,
        200,
        page(
          'GeeKEN Gate Smoke Client',
          '<p><a href="/login">Start OIDC Authorization Code login</a></p>',
        ),
      )
      return
    }

    if (requestUrl.pathname === '/login') {
      const pkce = createPkce()
      pkceStore.set(pkce.state, {
        verifier: pkce.verifier,
        nonce: pkce.nonce,
      })
      writeRedirect(response, buildAuthorizeUrl(config, pkce))
      return
    }

    if (requestUrl.pathname !== '/callback') {
      writeHtml(response, 404, page('Not Found', '<p>Route not found.</p>'))
      return
    }

    const errors = requestUrl.searchParams.getAll('error')

    if (errors.length > 0) {
      const message =
        errors.length === 1 && errors[0]
          ? escapeHtml(errors[0])
          : 'Invalid OAuth error response'
      writeHtml(
        response,
        400,
        page('OAuth Failed', `<p class="error">${message}</p>`),
      )
      return
    }

    const codes = requestUrl.searchParams.getAll('code')
    const states = requestUrl.searchParams.getAll('state')

    if (codes.length !== 1 || !codes[0]) {
      writeHtml(
        response,
        400,
        page(
          'OAuth Failed',
          '<p class="error">The callback did not contain exactly one authorization code.</p>',
        ),
      )
      return
    }

    const code = codes[0]
    const state = states.length === 1 ? states[0] : null
    const pkce = state !== null ? pkceStore.get(state) : undefined

    if (!pkce) {
      writeHtml(
        response,
        400,
        page(
          'OAuth Failed',
          '<p class="error">The callback state did not match a pending login.</p>',
        ),
      )
      return
    }

    pkceStore.delete(state)
    const secrets = [code, pkce.verifier]

    try {
      const first = await requestExchange(config, code, pkce.verifier)
      const second = await requestExchange(config, code, pkce.verifier)
      const firstSummary = first.ok
        ? '<p class="ok"><strong>First token request succeeded.</strong></p>'
        : '<p class="error"><strong>First token request failed.</strong></p>'
      const secondSummary = second.ok
        ? '<p class="error"><strong>ERROR: Reusing the code unexpectedly succeeded.</strong></p>'
        : '<p class="ok"><strong>Second token request failed as expected.</strong></p>'

      let userinfoSection = ''
      let userinfoOk = false
      if (
        first.ok &&
        typeof first.body === 'object' &&
        first.body !== null
      ) {
        if (typeof first.body.access_token === 'string') {
          secrets.push(first.body.access_token)
        }
        if (typeof first.body.refresh_token === 'string') {
          secrets.push(first.body.refresh_token)
        }
        const accessToken =
          typeof first.body.access_token === 'string'
            ? first.body.access_token
            : ''
        if (accessToken) {
          const userinfo = await requestUserinfo(config, accessToken)
          userinfoOk = userinfo.ok
          userinfoSection = renderResult('UserInfo', userinfo, secrets)
        }
      }

      writeHtml(
        response,
        first.ok && !second.ok && userinfoOk ? 200 : 502,
        page(
          'OIDC Smoke Test Result',
          `${firstSummary}
${renderResult('First token request', first, secrets)}
${secondSummary}
${renderResult('Second token request', second, secrets)}
${userinfoSection}`,
        ),
      )
    } catch {
      writeHtml(
        response,
        502,
        page(
          'OIDC Smoke Test Result',
          '<p class="error">The token request could not be completed.</p>',
        ),
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
    console.log(`Smoke client listening on http://localhost:${config.port}`)
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
