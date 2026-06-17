import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  buildAuthorizeUrl,
  createRequestHandler,
  escapeHtml,
  exchangeCode,
  fetchUserinfo,
  generatePKCE,
  loadConfig,
} from './smoke-client.mjs'

const ENVIRONMENT = {
  GATE_BASE_URL: 'https://gate.example/',
  SMOKE_CLIENT_ID: 'smoke-client',
  SMOKE_REDIRECT_URI: 'http://localhost:3000/callback',
}

function createConfig() {
  return loadConfig(ENVIRONMENT)
}

async function request(handler, target, method = 'GET') {
  const result = {
    status: 0,
    headers: {},
    body: '',
  }
  const response = {
    writeHead(status, headers) {
      result.status = status
      result.headers = headers
    },
    end(body = '') {
      result.body = body
    },
  }

  await handler(
    {
      method,
      url: target,
      headers: { host: 'localhost:3000' },
    },
    response,
  )

  return result
}

describe('smoke client configuration', () => {
  it('loads required values and defaults the port to 3000', () => {
    const config = createConfig()

    assert.equal(config.gateBaseUrl.href, 'https://gate.example/')
    assert.equal(config.clientId, 'smoke-client')
    assert.equal(config.redirectUri, 'http://localhost:3000/callback')
    assert.equal(config.port, 3000)
  })

  it('rejects missing required environment variables', () => {
    for (const name of Object.keys(ENVIRONMENT)) {
      const environment = { ...ENVIRONMENT }
      delete environment[name]

      assert.throws(() => loadConfig(environment), new RegExp(name))
    }
  })

  it('requires the redirect URI to match the localhost port and callback path', () => {
    for (const redirectUri of [
      'https://localhost:3000/callback',
      'http://127.0.0.1:3000/callback',
      'http://localhost:3001/callback',
      'http://localhost:3000/other',
    ]) {
      assert.throws(() =>
        loadConfig({
          ...ENVIRONMENT,
          SMOKE_REDIRECT_URI: redirectUri,
        }),
      )
    }
  })
})

describe('smoke client requests', () => {
  it('builds an authorize URL with PKCE and no client secret', () => {
    const pkce = generatePKCE()
    const authorizeUrl = new URL(buildAuthorizeUrl(createConfig(), pkce))

    assert.equal(authorizeUrl.origin + authorizeUrl.pathname, 'https://gate.example/authorize')
    assert.equal(authorizeUrl.searchParams.get('client_id'), 'smoke-client')
    assert.equal(
      authorizeUrl.searchParams.get('redirect_uri'),
      'http://localhost:3000/callback',
    )
    assert.equal(authorizeUrl.searchParams.get('response_type'), 'code')
    assert.equal(authorizeUrl.searchParams.get('scope'), 'openid')
    assert.equal(authorizeUrl.searchParams.get('state'), pkce.state)
    assert.equal(authorizeUrl.searchParams.get('nonce'), pkce.nonce)
    assert.equal(authorizeUrl.searchParams.get('code_challenge'), pkce.challenge)
    assert.equal(authorizeUrl.searchParams.get('code_challenge_method'), 'S256')
    assert.equal(authorizeUrl.searchParams.get('provider'), 'github')
  })

  it('uses public client form data for code exchange', async () => {
    const calls = []
    const result = await exchangeCode(
      createConfig(),
      'authorization-code',
      'verifier',
      async (url, options) => {
        calls.push({ url, options })
        return new Response(
          JSON.stringify({
            access_token: 'token123',
            token_type: 'Bearer',
            expires_in: 900,
            id_token: 'jwt',
            refresh_token: 'refresh',
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        )
      },
    )

    assert.equal(calls.length, 1)
    assert.equal(calls[0].url.href, 'https://gate.example/token')
    assert.equal(calls[0].options.method, 'POST')
    assert.equal(calls[0].options.headers.Authorization, undefined)
    assert.equal(
      calls[0].options.headers['Content-Type'],
      'application/x-www-form-urlencoded',
    )
    const body = calls[0].options.body.toString()
    assert.match(body, /grant_type=authorization_code/)
    assert.match(body, /code=authorization-code/)
    assert.match(body, /code_verifier=verifier/)
    assert.doesNotMatch(body, /client_secret/)
    assert.deepEqual(result, {
      status: 200,
      ok: true,
      body: {
        access_token: 'token123',
        token_type: 'Bearer',
        expires_in: 900,
        id_token: 'jwt',
        refresh_token: 'refresh',
      },
    })
  })

  it('fetches userinfo with a Bearer token', async () => {
    const calls = []
    const result = await fetchUserinfo(
      createConfig(),
      'token123',
      async (url, options) => {
        calls.push({ url, options })
        return new Response(JSON.stringify({ sub: 'user-id' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      },
    )

    assert.equal(calls.length, 1)
    assert.equal(calls[0].url.href, 'https://gate.example/userinfo')
    assert.equal(calls[0].options.headers.Authorization, 'Bearer token123')
    assert.deepEqual(result, {
      status: 200,
      ok: true,
      body: { sub: 'user-id' },
    })
  })

  it('renders the home page and redirects login to GeeKEN Gate', async () => {
    const handler = createRequestHandler(createConfig())
    const home = await request(handler, '/')
    const login = await request(handler, '/login')

    assert.equal(home.status, 200)
    assert.match(home.body, /Start OIDC Authorization Code login/)
    assert.equal(login.status, 302)
    const location = new URL(login.headers.Location)
    assert.equal(location.pathname, '/authorize')
    assert.equal(location.searchParams.get('client_id'), 'smoke-client')
    assert.equal(location.searchParams.get('response_type'), 'code')
    assert.equal(location.searchParams.get('provider'), 'github')
  })

  it('exchanges the callback code twice and reports expected reuse failure', async () => {
    const store = new Map()
    const pkce = generatePKCE()
    store.set(pkce.state, { verifier: pkce.verifier, nonce: pkce.nonce })

    const calls = []
    const handler = createRequestHandler(createConfig(), {
      pkceStore: store,
      exchangeCode: async (_config, code) => {
        calls.push(code)

        if (calls.length === 1) {
          return {
            status: 200,
            ok: true,
            body: {
              access_token: 'token123',
              token_type: 'Bearer',
              expires_in: 900,
              id_token: 'jwt',
              refresh_token: 'refresh',
            },
          }
        }

        return {
          status: 400,
          ok: false,
          body: { error: 'invalid_grant' },
        }
      },
      fetchUserinfo: async () => ({
        status: 200,
        ok: true,
        body: { sub: 'user-id' },
      }),
    })
    const result = await request(
      handler,
      `/callback?code=authorization-code&state=${pkce.state}`,
    )

    assert.equal(result.status, 200)
    assert.deepEqual(calls, [
      'authorization-code',
      'authorization-code',
    ])
    assert.match(result.body, /First token request succeeded/)
    assert.match(result.body, /Second token request failed as expected/)
    assert.match(result.body, /UserInfo/)
    assert.match(result.body, /\[REDACTED\]/)
    assert.doesNotMatch(result.body, /authorization-code/)
    assert.doesNotMatch(result.body, /refresh/)
  })

  it('marks UserInfo failure as an overall smoke failure', async () => {
    const store = new Map()
    const pkce = generatePKCE()
    store.set(pkce.state, { verifier: pkce.verifier, nonce: pkce.nonce })

    const calls = []
    const handler = createRequestHandler(createConfig(), {
      pkceStore: store,
      exchangeCode: async (_config, code) => {
        calls.push(code)

        if (calls.length === 1) {
          return {
            status: 200,
            ok: true,
            body: {
              access_token: 'token123',
              token_type: 'Bearer',
              expires_in: 900,
              id_token: 'jwt',
              refresh_token: 'refresh',
            },
          }
        }

        return {
          status: 400,
          ok: false,
          body: { error: 'invalid_grant' },
        }
      },
      fetchUserinfo: async () => ({
        status: 401,
        ok: false,
        body: { error: 'invalid_token' },
      }),
    })
    const result = await request(
      handler,
      `/callback?code=authorization-code&state=${pkce.state}`,
    )

    assert.equal(result.status, 502)
    assert.match(result.body, /UserInfo/)
    assert.match(result.body, /invalid_token/)
  })

  it('marks a successful second exchange as an error', async () => {
    const store = new Map()
    const pkce = generatePKCE()
    store.set(pkce.state, { verifier: pkce.verifier, nonce: pkce.nonce })

    const handler = createRequestHandler(createConfig(), {
      pkceStore: store,
      exchangeCode: async () => ({
        status: 200,
        ok: true,
        body: { unexpected: true },
      }),
    })
    const result = await request(
      handler,
      `/callback?code=authorization-code&state=${pkce.state}`,
    )

    assert.equal(result.status, 502)
    assert.match(result.body, /unexpectedly succeeded/)
  })

  it('shows callback errors without exchanging a code', async () => {
    let exchangeCalled = false
    const handler = createRequestHandler(createConfig(), {
      exchangeCode: async () => {
        exchangeCalled = true
      },
    })
    const errorResult = await request(
      handler,
      '/callback?error=%3Caccess_denied%3E',
    )
    const missingCodeResult = await request(handler, '/callback')

    assert.equal(errorResult.status, 400)
    assert.match(errorResult.body, /&lt;access_denied&gt;/)
    assert.equal(missingCodeResult.status, 400)
    assert.equal(exchangeCalled, false)
  })

  it('escapes HTML special characters', () => {
    assert.equal(
      escapeHtml(`<script a="b">'&</script>`),
      '&lt;script a=&quot;b&quot;&gt;&#39;&amp;&lt;/script&gt;',
    )
  })
})
