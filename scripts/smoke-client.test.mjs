import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  buildAuthorizeUrl,
  createRequestHandler,
  escapeHtml,
  exchangeCode,
  loadConfig,
} from './smoke-client.mjs'

const ENVIRONMENT = {
  GATE_BASE_URL: 'https://gate.example/',
  SMOKE_CLIENT_ID: 'smoke-client',
  SMOKE_CLIENT_SECRET: 'private-client-secret',
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
    assert.equal(config.clientSecret, 'private-client-secret')
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
  it('builds an authorize URL without the client secret', () => {
    const loginUrl = new URL(buildAuthorizeUrl(createConfig()))

    assert.equal(loginUrl.origin + loginUrl.pathname, 'https://gate.example/authorize')
    assert.equal(loginUrl.searchParams.get('response_type'), 'code')
    assert.equal(loginUrl.searchParams.get('client_id'), 'smoke-client')
    assert.equal(loginUrl.searchParams.get('redirect_uri'), 'http://localhost:3000/callback')
    assert.equal(loginUrl.searchParams.get('scope'), 'openid')
    assert.equal(loginUrl.searchParams.get('provider'), 'github')
    assert.ok(loginUrl.searchParams.get('state'))
    assert.ok(loginUrl.searchParams.get('nonce'))
    assert.doesNotMatch(loginUrl.href, /private-client-secret/)
  })

  it('uses Basic authentication and form data for token exchange', async () => {
    const calls = []
    const result = await exchangeCode(
      createConfig(),
      'authorization-code',
      async (url, options) => {
        calls.push({ url, options })
        return new Response(
          JSON.stringify({
            access_token: 'access-token',
            token_type: 'Bearer',
            id_token: 'header.payload.signature',
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
    assert.equal(
      calls[0].options.headers.Authorization,
      `Basic ${Buffer.from(
        'smoke-client:private-client-secret',
      ).toString('base64')}`,
    )
    assert.equal(
      calls[0].options.headers['Content-Type'],
      'application/x-www-form-urlencoded',
    )
    assert.equal(
      calls[0].options.body.toString(),
      'grant_type=authorization_code&code=authorization-code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback',
    )
    assert.deepEqual(result, {
      status: 200,
      ok: true,
      body: {
        access_token: 'access-token',
        token_type: 'Bearer',
        id_token: 'header.payload.signature',
      },
    })
  })

  it('renders the home page and redirects login to GeeKEN Gate', async () => {
    const handler = createRequestHandler(createConfig())
    const home = await request(handler, '/')
    const login = await request(handler, '/login')

    assert.equal(home.status, 200)
    assert.match(home.body, /Start OIDC login through GitHub/)
    assert.doesNotMatch(home.body, /private-client-secret/)
    assert.equal(login.status, 302)
    assert.equal(
      new URL(login.headers.Location).origin + new URL(login.headers.Location).pathname,
      'https://gate.example/authorize',
    )
    assert.doesNotMatch(login.headers.Location, /private-client-secret/)
  })

  it('exchanges the callback code twice and reports expected reuse failure', async () => {
    const calls = []
    const handler = createRequestHandler(createConfig(), {
      exchangeCode: async (_config, code) => {
        calls.push(code)

        if (calls.length === 1) {
          return {
            status: 200,
            ok: true,
            body: {
              github_id: '123<script>',
              github_login: 'octo&cat',
              reflected_code: code,
              reflected_secret: 'private-client-secret',
            },
          }
        }

        return {
          status: 400,
          ok: false,
          body: { error: 'invalid_grant' },
        }
      },
    })
    const result = await request(handler, '/callback?code=authorization-code')

    assert.equal(result.status, 200)
    assert.deepEqual(calls, ['authorization-code', 'authorization-code'])
    assert.match(result.body, /First exchange succeeded/)
    assert.match(result.body, /Second exchange failed as expected/)
    assert.match(result.body, /123&lt;script&gt;/)
    assert.match(result.body, /octo&amp;cat/)
    assert.match(result.body, /\[REDACTED\]/)
    assert.doesNotMatch(result.body, /authorization-code/)
    assert.doesNotMatch(result.body, /private-client-secret/)
  })

  it('marks a successful second exchange as an error', async () => {
    const handler = createRequestHandler(createConfig(), {
      exchangeCode: async () => ({
        status: 200,
        ok: true,
        body: { unexpected: true },
      }),
    })
    const result = await request(handler, '/callback?code=authorization-code')

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
      '/callback?error=%3Caccess_denied%3Eprivate-client-secret',
    )
    const missingCodeResult = await request(handler, '/callback')

    assert.equal(errorResult.status, 400)
    assert.match(errorResult.body, /&lt;access_denied&gt;\[REDACTED\]/)
    assert.doesNotMatch(errorResult.body, /private-client-secret/)
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
