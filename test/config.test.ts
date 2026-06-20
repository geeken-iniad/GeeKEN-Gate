import { describe, expect, it } from 'vitest'

import {
  type AppBindings,
  loadAuthServerConfig,
} from '../src/lib/config'
import { TEST_KID, TEST_PRIVATE_JWK } from './fixtures/jwk'
import { allowingRateLimiter } from './rate-limit'

const database = {
  prepare() {},
  batch() {},
} as unknown as D1Database
const TOKEN_HASH_SECRET = 't'.repeat(32)
const GITHUB_CALLBACK_URL = 'https://auth.example.com/callback/github'

function createBindings(
  overrides: Partial<AppBindings> = {},
): AppBindings {
  return {
    DB: database,
    PUBLIC_RATE_LIMITER: allowingRateLimiter,
    CLIENT_RATE_LIMITER: allowingRateLimiter,
    GITHUB_CLIENT_ID: 'github-client-id',
    GITHUB_CLIENT_SECRET: 'github-client-secret',
    GITHUB_ORG: 'example-org',
    GITHUB_CALLBACK_URL,
    OIDC_ISSUER: 'https://auth.example.com',
    OIDC_SIGNING_PRIVATE_KEY: JSON.stringify(TEST_PRIVATE_JWK),
    OIDC_SIGNING_KEY_ID: TEST_KID,
    TOKEN_HASH_SECRET,
    ...overrides,
  }
}

describe('loadAuthServerConfig', () => {
  it('returns validated OIDC authentication server configuration', async () => {
    const config = await loadAuthServerConfig(createBindings())

    expect(config.db).toBe(database)
    expect(config.githubClientId).toBe('github-client-id')
    expect(config.githubCallbackUrl.href).toBe(GITHUB_CALLBACK_URL)
    expect(config.tokenHashSecret).toBe(TOKEN_HASH_SECRET)
    expect(config.issuer.href).toBe('https://auth.example.com/')
    expect(config.keyId).toBe(TEST_KID)
    expect(config.publicJwk).toMatchObject({
      kty: 'RSA',
      alg: 'RS256',
      use: 'sig',
      kid: TEST_KID,
    })
  })

  it.each([
    'GITHUB_CLIENT_ID',
    'GITHUB_CLIENT_SECRET',
    'GITHUB_ORG',
    'GITHUB_CALLBACK_URL',
    'OIDC_ISSUER',
    'OIDC_SIGNING_PRIVATE_KEY',
    'OIDC_SIGNING_KEY_ID',
    'TOKEN_HASH_SECRET',
  ] as const)('rejects a missing %s binding', async (name) => {
    const bindings = createBindings()
    delete bindings[name]

    await expect(() => loadAuthServerConfig(bindings)).rejects.toThrow(
      `Missing or empty environment binding: ${name}`,
    )
  })

  it.each([
    'GITHUB_CLIENT_ID',
    'GITHUB_CLIENT_SECRET',
    'GITHUB_ORG',
    'GITHUB_CALLBACK_URL',
    'OIDC_ISSUER',
    'OIDC_SIGNING_PRIVATE_KEY',
    'OIDC_SIGNING_KEY_ID',
    'TOKEN_HASH_SECRET',
  ] as const)('rejects an empty %s binding', async (name) => {
    await expect(() =>
      loadAuthServerConfig(createBindings({ [name]: '   ' })),
    ).rejects.toThrow(`Missing or empty environment binding: ${name}`)
  })

  it.each([
    'not-a-url',
    'ftp://auth.example.com/callback',
    'http://auth.example.com/callback',
    'http://localhost.evil.example/callback',
  ])('rejects an invalid callback URL: %s', async (callbackUrl) => {
    await expect(() =>
      loadAuthServerConfig(
        createBindings({ GITHUB_CALLBACK_URL: callbackUrl }),
      ),
    ).rejects.toThrow('Invalid environment binding: GITHUB_CALLBACK_URL')
  })

  it.each([
    'http://localhost:8787/callback/github',
    'http://127.0.0.1:8787/callback/github',
    'http://[::1]:8787/callback/github',
  ])('allows a loopback HTTP callback URL: %s', async (callbackUrl) => {
    const config = await loadAuthServerConfig(
      createBindings({
        GITHUB_CALLBACK_URL: callbackUrl,
      }),
    )

    expect(config.githubCallbackUrl.href).toBe(callbackUrl)
  })

  it.each([
    ['issuer with query', 'https://auth.example.com?foo=1'],
    ['issuer with fragment', 'https://auth.example.com#frag'],
    ['issuer with non-HTTPS/non-loopback', 'http://auth.example.com'],
  ])('rejects an invalid OIDC issuer: %s', async (_caseName, issuer) => {
    await expect(
      loadAuthServerConfig(createBindings({ OIDC_ISSUER: issuer })),
    ).rejects.toThrow('Invalid environment binding: OIDC_ISSUER')
  })

  it('allows a loopback HTTP OIDC issuer for local development', async () => {
    const config = await loadAuthServerConfig(
      createBindings({ OIDC_ISSUER: 'http://127.0.0.1:8787' }),
    )

    expect(config.issuer.href).toBe('http://127.0.0.1:8787/')
  })

  it.each([
    ['31 ASCII bytes', 't'.repeat(31)],
    ['30 UTF-8 bytes', 'あ'.repeat(10)],
  ])(
    'rejects a TOKEN_HASH_SECRET shorter than 32 bytes: %s',
    async (_caseName, secret) => {
      await expect(
        loadAuthServerConfig(createBindings({ TOKEN_HASH_SECRET: secret })),
      ).rejects.toThrow(
        'Invalid environment binding: TOKEN_HASH_SECRET must be at least 32 UTF-8 bytes',
      )
    },
  )

  it('rejects an invalid RSA private JWK', async () => {
    await expect(
      loadAuthServerConfig(
        createBindings({ OIDC_SIGNING_PRIVATE_KEY: 'not-json' }),
      ),
    ).rejects.toThrow('Invalid environment binding: OIDC_SIGNING_PRIVATE_KEY')

    await expect(
      loadAuthServerConfig(
        createBindings({ OIDC_SIGNING_PRIVATE_KEY: JSON.stringify({ kty: 'oct' }) }),
      ),
    ).rejects.toThrow('Invalid environment binding: OIDC_SIGNING_PRIVATE_KEY')
  })

  it.each([undefined, null, {}, { prepare() {} }])(
    'rejects a missing or invalid D1 binding',
    async (invalidDatabase) => {
      const bindings = createBindings()
      bindings.DB = invalidDatabase as unknown as D1Database

      await expect(() => loadAuthServerConfig(bindings)).rejects.toThrow(
        'Missing or invalid environment binding: DB',
      )
    },
  )
})
