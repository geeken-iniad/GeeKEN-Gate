import { describe, expect, it } from 'vitest'

import {
  type AppBindings,
  loadAuthServerConfig,
} from '../src/lib/config'
import { allowingRateLimiter } from './rate-limit'

const database = {
  prepare() {},
  batch() {},
} as unknown as D1Database
const SESSION_SECRET = 's'.repeat(32)

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
    GITHUB_CALLBACK_URL: 'https://auth.example.com/callback',
    SESSION_SECRET,
    ...overrides,
  }
}

describe('loadAuthServerConfig', () => {
  it('returns validated authentication server configuration', () => {
    const config = loadAuthServerConfig(createBindings())

    expect(config).toEqual({
      db: database,
      githubClientId: 'github-client-id',
      githubClientSecret: 'github-client-secret',
      githubOrg: 'example-org',
      githubCallbackUrl: new URL('https://auth.example.com/callback'),
      sessionSecret: SESSION_SECRET,
    })
  })

  it.each([
    'GITHUB_CLIENT_ID',
    'GITHUB_CLIENT_SECRET',
    'GITHUB_ORG',
    'GITHUB_CALLBACK_URL',
    'SESSION_SECRET',
  ] as const)('rejects a missing %s binding', (name) => {
    const bindings = createBindings()
    delete bindings[name]

    expect(() => loadAuthServerConfig(bindings)).toThrow(
      `Missing or empty environment binding: ${name}`,
    )
  })

  it.each([
    'GITHUB_CLIENT_ID',
    'GITHUB_CLIENT_SECRET',
    'GITHUB_ORG',
    'GITHUB_CALLBACK_URL',
    'SESSION_SECRET',
  ] as const)('rejects an empty %s binding', (name) => {
    expect(() =>
      loadAuthServerConfig(createBindings({ [name]: '   ' })),
    ).toThrow(`Missing or empty environment binding: ${name}`)
  })

  it.each([
    'not-a-url',
    'ftp://auth.example.com/callback',
    'http://auth.example.com/callback',
    'http://localhost.evil.example/callback',
  ])('rejects an invalid callback URL: %s', (callbackUrl) => {
    expect(() =>
      loadAuthServerConfig(
        createBindings({ GITHUB_CALLBACK_URL: callbackUrl }),
      ),
    ).toThrow('Invalid environment binding: GITHUB_CALLBACK_URL')
  })

  it.each([
    'http://localhost:8787/callback',
    'http://127.0.0.1:8787/callback',
    'http://[::1]:8787/callback',
  ])('allows a loopback HTTP callback URL: %s', (callbackUrl) => {
    const config = loadAuthServerConfig(
      createBindings({
        GITHUB_CALLBACK_URL: callbackUrl,
      }),
    )

    expect(config.githubCallbackUrl.href).toBe(callbackUrl)
  })

  it.each([
    ['31 ASCII bytes', 's'.repeat(31)],
    ['30 UTF-8 bytes', 'あ'.repeat(10)],
  ])(
    'rejects a SESSION_SECRET shorter than 32 bytes: %s',
    (_caseName, secret) => {
      expect(() =>
        loadAuthServerConfig(createBindings({ SESSION_SECRET: secret })),
      ).toThrow(
        'Invalid environment binding: SESSION_SECRET must be at least 32 UTF-8 bytes',
      )
    },
  )

  it.each([
    ['32 ASCII bytes', 's'.repeat(32)],
    ['33 UTF-8 bytes', 'あ'.repeat(11)],
  ])(
    'allows a SESSION_SECRET of at least 32 bytes: %s',
    (_caseName, secret) => {
      expect(
        loadAuthServerConfig(createBindings({ SESSION_SECRET: secret }))
          .sessionSecret,
      ).toBe(secret)
    },
  )

  it.each([undefined, null, {}, { prepare() {} }])(
    'rejects a missing or invalid D1 binding',
    (invalidDatabase) => {
      const bindings = createBindings()
      bindings.DB = invalidDatabase as unknown as D1Database

      expect(() => loadAuthServerConfig(bindings)).toThrow(
        'Missing or invalid environment binding: DB',
      )
    },
  )
})
