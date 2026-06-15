import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  buildAuthorizeUrl,
  createPkce,
  createRequestHandler,
  escapeHtml,
  exchangeCode,
  fetchDiscovery,
  fetchUserinfo,
  loadConfig,
  verifyIdToken,
} from './smoke-client.mjs'

const ENVIRONMENT = {
  GATE_BASE_URL: 'https://gate.example/',
  SMOKE_CLIENT_ID: 'smoke-client',
  SMOKE_CLIENT_SECRET: 'private-client-secret',
  SMOKE_REDIRECT_URI: 'http://localhost:3000/callback',
}

const DISCOVERY = {
  issuer: 'https://gate.example',
  authorization_endpoint: 'https://gate.example/authorize',
  token_endpoint: 'https://gate.example/token',
  jwks_uri: 'https://gate.example/jwks.json',
  userinfo_endpoint: 'https://gate.example/userinfo',
}

const textEncoder = new TextEncoder()

function createConfig(overrides = {}) {
  return loadConfig({ ...ENVIRONMENT, ...overrides })
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

function base64Url(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '')
}

function base64UrlJson(value) {
  return base64Url(textEncoder.encode(JSON.stringify(value)))
}

async function createSignedIdToken(claimOverrides = {}) {
  const keys = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )
  const publicJwk = await crypto.subtle.exportKey('jwk', keys.publicKey)
  publicJwk.kid = 'test-key'
  publicJwk.alg = 'ES256'
  publicJwk.use = 'sig'
  publicJwk.key_ops = ['verify']
  const now = Math.floor(Date.now() / 1000)
  const claims = {
    iss: 'https://gate.example',
    sub: 'geeken-user-123',
    aud: 'smoke-client',
    exp: now + 300,
    iat: now,
    auth_time: now,
    nonce: 'nonce-value',
    ...claimOverrides,
  }
  const header = { alg: 'ES256', typ: 'JWT', kid: 'test-key' }
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(claims)}`
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keys.privateKey,
    textEncoder.encode(signingInput),
  )

  return {
    idToken: `${signingInput}.${base64Url(new Uint8Array(signature))}`,
    jwks: { keys: [publicJwk] },
    claims,
  }
}

describe('smoke client configuration', () => {
  it('loads required values and defaults provider/userinfo', () => {
    const config = createConfig()

    assert.equal(config.gateBaseUrl.href, 'https://gate.example/')
    assert.equal(config.clientId, 'smoke-client')
    assert.equal(config.clientSecret, 'private-client-secret')
    assert.equal(config.redirectUri, 'http://localhost:3000/callback')
    assert.equal(config.port, 3000)
    assert.equal(config.provider, 'github')
    assert.equal(config.callUserinfo, true)
  })

  it('supports google provider selection', () => {
    assert.equal(createConfig({ SMOKE_PROVIDER: 'google' }).provider, 'google')
    assert.throws(() => createConfig({ SMOKE_PROVIDER: 'gitlab' }), /SMOKE_PROVIDER/)
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

describe('OIDC protocol helpers', () => {
  it('loads and validates discovery metadata', async () => {
    const calls = []
    const discovery = await fetchDiscovery(createConfig(), async (url) => {
      calls.push(url.href)
      return Response.json(DISCOVERY)
    })

    assert.deepEqual(calls, ['https://gate.example/.well-known/openid-configuration'])
    assert.equal(discovery.issuer, 'https://gate.example')
    await assert.rejects(
      () => fetchDiscovery(createConfig(), async () => Response.json({ ...DISCOVERY, issuer: 'https://evil.example' })),
      /issuer/,
    )
  })

  it('builds an authorize URL with provider and PKCE without the client secret', () => {
    const loginUrl = new URL(buildAuthorizeUrl(createConfig({ SMOKE_PROVIDER: 'google' }), DISCOVERY, {
      state: 'state-value',
      nonce: 'nonce-value',
      provider: 'google',
      codeChallenge: 'a'.repeat(43),
      codeChallengeMethod: 'S256',
    }))

    assert.equal(loginUrl.origin + loginUrl.pathname, 'https://gate.example/authorize')
    assert.equal(loginUrl.searchParams.get('response_type'), 'code')
    assert.equal(loginUrl.searchParams.get('client_id'), 'smoke-client')
    assert.equal(loginUrl.searchParams.get('redirect_uri'), 'http://localhost:3000/callback')
    assert.equal(loginUrl.searchParams.get('scope'), 'openid')
    assert.equal(loginUrl.searchParams.get('provider'), 'google')
    assert.equal(loginUrl.searchParams.get('state'), 'state-value')
    assert.equal(loginUrl.searchParams.get('nonce'), 'nonce-value')
    assert.equal(loginUrl.searchParams.get('code_challenge'), 'a'.repeat(43))
    assert.equal(loginUrl.searchParams.get('code_challenge_method'), 'S256')
    assert.doesNotMatch(loginUrl.href, /private-client-secret/)
  })

  it('generates S256 PKCE verifier and challenge', async () => {
    const pkce = await createPkce()

    assert.match(pkce.codeVerifier, /^[A-Za-z0-9_-]{43,128}$/)
    assert.match(pkce.codeChallenge, /^[A-Za-z0-9_-]{43,128}$/)
    assert.equal(pkce.codeChallengeMethod, 'S256')
    assert.notEqual(pkce.codeVerifier, pkce.codeChallenge)
  })

  it('uses Basic authentication, form data, and code_verifier for token exchange', async () => {
    const calls = []
    const result = await exchangeCode(
      createConfig(),
      DISCOVERY,
      'authorization-code',
      'verifier-value',
      async (url, options) => {
        calls.push({ url, options })
        return Response.json({
          access_token: 'access-token',
          token_type: 'Bearer',
          id_token: 'header.payload.signature',
        })
      },
    )

    assert.equal(calls.length, 1)
    assert.equal(calls[0].url.href, 'https://gate.example/token')
    assert.equal(calls[0].options.method, 'POST')
    assert.equal(
      calls[0].options.headers.Authorization,
      `Basic ${Buffer.from('smoke-client:private-client-secret').toString('base64')}`,
    )
    assert.equal(calls[0].options.headers['Content-Type'], 'application/x-www-form-urlencoded')
    assert.equal(
      calls[0].options.body.toString(),
      'grant_type=authorization_code&code=authorization-code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&code_verifier=verifier-value',
    )
    assert.deepEqual(result.body, {
      access_token: 'access-token',
      token_type: 'Bearer',
      id_token: 'header.payload.signature',
    })
  })

  it('verifies ID Token signature and claims from JWKS', async () => {
    const { idToken, jwks } = await createSignedIdToken()
    const claims = await verifyIdToken(idToken, jwks, {
      issuer: 'https://gate.example',
      clientId: 'smoke-client',
      nonce: 'nonce-value',
    })

    assert.equal(claims.sub, 'geeken-user-123')
    await assert.rejects(
      () => verifyIdToken(idToken, jwks, { issuer: 'https://gate.example', clientId: 'other', nonce: 'nonce-value' }),
      /aud/,
    )
    await assert.rejects(
      () => verifyIdToken(idToken, jwks, { issuer: 'https://gate.example', clientId: 'smoke-client', nonce: 'wrong' }),
      /nonce/,
    )
    await assert.rejects(
      () => verifyIdToken(idToken, { keys: [{ ...jwks.keys[0], kid: 'other-key' }] }, { issuer: 'https://gate.example', clientId: 'smoke-client', nonce: 'nonce-value' }),
      /No JWKS key/,
    )
  })

  it('rejects ID Tokens with missing, invalid, future, or array auth_time/aud claims', async () => {
    const now = Math.floor(Date.now() / 1000)
    for (const [overrides, pattern] of [
      [{ auth_time: undefined }, /auth_time/],
      [{ auth_time: 'not-a-number' }, /auth_time/],
      [{ auth_time: now + 120 }, /auth_time/],
      [{ aud: ['smoke-client'] }, /aud/],
      [{ aud: ['smoke-client', 'other-client'] }, /aud/],
    ]) {
      const { idToken, jwks } = await createSignedIdToken(overrides)

      await assert.rejects(
        () => verifyIdToken(idToken, jwks, {
          issuer: 'https://gate.example',
          clientId: 'smoke-client',
          nonce: 'nonce-value',
        }),
        pattern,
      )
    }
  })

  it('calls userinfo with bearer token and parses error bodies', async () => {
    const ok = await fetchUserinfo(DISCOVERY, 'access-token', async (url, options) => {
      assert.equal(url.href, 'https://gate.example/userinfo')
      assert.equal(options.headers.Authorization, 'Bearer access-token')
      return Response.json({ sub: 'geeken-user-123' })
    })
    const failed = await fetchUserinfo(DISCOVERY, 'access-token', async () => Response.json({ error: 'invalid_token' }, { status: 401 }))

    assert.deepEqual(ok.body, { sub: 'geeken-user-123' })
    assert.equal(failed.ok, false)
    assert.deepEqual(failed.body, { error: 'invalid_token' })
  })
})

describe('smoke client requests', () => {
  it('renders the home page and redirects start to discovered authorize endpoint', async () => {
    const handler = createRequestHandler(createConfig(), {
      fetchDiscovery: async () => DISCOVERY,
    })
    const home = await request(handler, '/')
    const start = await request(handler, '/start?provider=google')

    assert.equal(home.status, 200)
    assert.match(home.body, /Authorization Code \+ PKCE/)
    assert.match(home.body, /Start OIDC login through github/)
    assert.doesNotMatch(home.body, /private-client-secret/)
    assert.equal(start.status, 302)
    const location = new URL(start.headers.Location)
    assert.equal(location.origin + location.pathname, 'https://gate.example/authorize')
    assert.equal(location.searchParams.get('provider'), 'google')
    assert.ok(location.searchParams.get('code_challenge'))
    assert.equal(location.searchParams.get('code_challenge_method'), 'S256')
    assert.doesNotMatch(start.headers.Location, /private-client-secret/)
  })

  it('exchanges callback code, verifies ID Token, displays sub, and displays userinfo sub', async () => {
    const { idToken, jwks } = await createSignedIdToken()
    const transactions = new Map([
      ['state-value', {
        state: 'state-value', nonce: 'nonce-value', provider: 'github', codeVerifier: 'verifier-value', codeChallenge: 'challenge', codeChallengeMethod: 'S256',
      }],
    ])
    const handler = createRequestHandler(createConfig(), {
      transactions,
      fetchDiscovery: async () => DISCOVERY,
      exchangeCode: async (_config, _discovery, code, verifier) => {
        assert.equal(code, 'authorization-code')
        assert.equal(verifier, 'verifier-value')
        return { status: 200, ok: true, body: { access_token: 'access-token', id_token: idToken, token_type: 'Bearer' } }
      },
      fetchJwks: async () => jwks,
      fetchUserinfo: async (_discovery, accessToken) => {
        assert.equal(accessToken, 'access-token')
        return { status: 200, ok: true, body: { sub: 'geeken-user-123' } }
      },
    })
    const result = await request(handler, '/callback?state=state-value&code=authorization-code')

    assert.equal(result.status, 200)
    assert.match(result.body, /Token exchange and ID Token verification succeeded/)
    assert.match(result.body, /GeeKEN Gate sub:<\/strong> <code>geeken-user-123<\/code>/)
    assert.match(result.body, /UserInfo sub:<\/strong> <code>geeken-user-123<\/code>/)
    assert.doesNotMatch(result.body, /authorization-code/)
    assert.doesNotMatch(result.body, /private-client-secret/)
    assert.doesNotMatch(result.body, /access-token/)
    assert.doesNotMatch(result.body, new RegExp(idToken.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  })

  it('fails userinfo mismatch/request errors and token exchange errors without leaking secrets', async () => {
    const { idToken, jwks } = await createSignedIdToken()
    const transactions = new Map([
      ['state-value', { state: 'state-value', nonce: 'nonce-value', provider: 'github', codeVerifier: 'verifier-value' }],
      ['state-two', { state: 'state-two', nonce: 'nonce-value', provider: 'github', codeVerifier: 'verifier-value' }],
    ])
    const handler = createRequestHandler(createConfig(), {
      transactions,
      fetchDiscovery: async () => DISCOVERY,
      exchangeCode: async (_config, _discovery, code) => code === 'bad-code'
        ? { status: 400, ok: false, body: { error: 'invalid_grant', reflected: code, secret: 'private-client-secret' } }
        : { status: 200, ok: true, body: { access_token: 'access-token', id_token: idToken } },
      fetchJwks: async () => jwks,
      fetchUserinfo: async () => ({ status: 200, ok: true, body: { sub: 'other-sub', token: 'access-token' } }),
    })

    const mismatch = await request(handler, '/callback?state=state-value&code=authorization-code')
    const exchangeError = await request(handler, '/callback?state=state-two&code=bad-code')
    const handlerWithUserinfoFailure = createRequestHandler(createConfig(), {
      transactions: new Map([
        ['state-three', { state: 'state-three', nonce: 'nonce-value', provider: 'github', codeVerifier: 'verifier-value' }],
      ]),
      fetchDiscovery: async () => DISCOVERY,
      exchangeCode: async () => ({ status: 200, ok: true, body: { access_token: 'access-token', id_token: idToken } }),
      fetchJwks: async () => jwks,
      fetchUserinfo: async () => ({ status: 401, ok: false, body: { error: 'invalid_token', token: 'access-token' } }),
    })
    const userinfoError = await request(handlerWithUserinfoFailure, '/callback?state=state-three&code=authorization-code')

    assert.equal(mismatch.status, 502)
    assert.match(mismatch.body, /UserInfo sub did not match/)
    assert.doesNotMatch(mismatch.body, /Token exchange and ID Token verification succeeded/)
    assert.doesNotMatch(mismatch.body, /access-token/)
    assert.equal(userinfoError.status, 502)
    assert.match(userinfoError.body, /UserInfo request failed/)
    assert.doesNotMatch(userinfoError.body, /Token exchange and ID Token verification succeeded/)
    assert.doesNotMatch(userinfoError.body, /access-token/)
    assert.equal(exchangeError.status, 502)
    assert.match(exchangeError.body, /Token exchange failed/)
    assert.match(exchangeError.body, /\[REDACTED\]/)
    assert.doesNotMatch(exchangeError.body, /bad-code/)
    assert.doesNotMatch(exchangeError.body, /private-client-secret/)
  })

  it('fails when userinfo is enabled and the token response lacks a string access token', async () => {
    const { idToken, jwks } = await createSignedIdToken()
    const transactions = new Map([
      ['state-missing', { state: 'state-missing', nonce: 'nonce-value', provider: 'github', codeVerifier: 'verifier-value' }],
      ['state-non-string', { state: 'state-non-string', nonce: 'nonce-value', provider: 'github', codeVerifier: 'verifier-value' }],
    ])
    let userinfoCalled = false
    const handler = createRequestHandler(createConfig(), {
      transactions,
      fetchDiscovery: async () => DISCOVERY,
      exchangeCode: async (_config, _discovery, code) => code === 'non-string-token'
        ? { status: 200, ok: true, body: { access_token: 123, id_token: idToken } }
        : { status: 200, ok: true, body: { id_token: idToken } },
      fetchJwks: async () => jwks,
      fetchUserinfo: async () => {
        userinfoCalled = true
        return { status: 200, ok: true, body: { sub: 'geeken-user-123' } }
      },
    })

    const missing = await request(handler, '/callback?state=state-missing&code=missing-token')
    const nonString = await request(handler, '/callback?state=state-non-string&code=non-string-token')

    assert.equal(missing.status, 502)
    assert.match(missing.body, /usable access token/)
    assert.doesNotMatch(missing.body, /Token exchange and ID Token verification succeeded/)
    assert.equal(nonString.status, 502)
    assert.match(nonString.body, /usable access token/)
    assert.doesNotMatch(nonString.body, /Token exchange and ID Token verification succeeded/)
    assert.equal(userinfoCalled, false)
  })

  it('fails when userinfo is enabled and discovery lacks a usable userinfo endpoint', async () => {
    const { idToken, jwks } = await createSignedIdToken()
    const transactions = new Map([
      ['state-missing', { state: 'state-missing', nonce: 'nonce-value', provider: 'github', codeVerifier: 'verifier-value' }],
      ['state-non-string', { state: 'state-non-string', nonce: 'nonce-value', provider: 'github', codeVerifier: 'verifier-value' }],
    ])
    const discoveries = [
      Object.fromEntries(Object.entries(DISCOVERY).filter(([key]) => key !== 'userinfo_endpoint')),
      { ...DISCOVERY, userinfo_endpoint: 123 },
    ]
    const handler = createRequestHandler(createConfig(), {
      transactions,
      fetchDiscovery: async () => discoveries.shift(),
      exchangeCode: async () => ({ status: 200, ok: true, body: { access_token: 'access-token', id_token: idToken } }),
      fetchJwks: async () => jwks,
    })

    const missing = await request(handler, '/callback?state=state-missing&code=authorization-code')
    const nonString = await request(handler, '/callback?state=state-non-string&code=authorization-code')

    assert.equal(missing.status, 502)
    assert.match(missing.body, /Discovery document has no usable userinfo_endpoint/)
    assert.doesNotMatch(missing.body, /Token exchange and ID Token verification succeeded/)
    assert.equal(nonString.status, 502)
    assert.match(nonString.body, /Discovery document has no usable userinfo_endpoint/)
    assert.doesNotMatch(nonString.body, /Token exchange and ID Token verification succeeded/)
  })

  it('shows callback errors without exchanging a code', async () => {
    let exchangeCalled = false
    const handler = createRequestHandler(createConfig(), {
      transactions: new Map([['state-value', { state: 'state-value', nonce: 'nonce-value', provider: 'github', codeVerifier: 'verifier-value' }]]),
      exchangeCode: async () => {
        exchangeCalled = true
      },
    })
    const errorResult = await request(
      handler,
      '/callback?state=state-value&error=%3Caccess_denied%3Eprivate-client-secret',
    )
    const missingStateResult = await request(handler, '/callback?code=authorization-code')

    assert.equal(errorResult.status, 400)
    assert.match(errorResult.body, /&lt;access_denied&gt;\[REDACTED\]/)
    assert.doesNotMatch(errorResult.body, /private-client-secret/)
    assert.equal(missingStateResult.status, 400)
    assert.equal(exchangeCalled, false)
  })

  it('escapes HTML special characters', () => {
    assert.equal(
      escapeHtml(`<script a="b">'&</script>`),
      '&lt;script a=&quot;b&quot;&gt;&#39;&amp;&lt;/script&gt;',
    )
  })
})
