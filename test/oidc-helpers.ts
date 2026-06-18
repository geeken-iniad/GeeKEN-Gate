import { env } from 'cloudflare:workers'

import type { AppBindings } from '../src/lib/config'
import { TEST_KID, TEST_PRIVATE_JWK } from './fixtures/jwk'
import { allowingRateLimiter } from './rate-limit'

export const NOW = 1_700_000_000
export const CLIENT_ID = 'client-a'
export const REDIRECT_URI = 'https://client.example/callback'
export const TOKEN_HASH_SECRET = 's'.repeat(32)
export const GITHUB_CALLBACK_URL = 'https://auth.example.com/callback/github'
export const GOOGLE_CALLBACK_URL = 'https://auth.example.com/callback/google'
export const ISSUER = 'https://auth.example.com'
export const GOOGLE_CLIENT_ID = 'google-client-id'
export const GOOGLE_CLIENT_SECRET = 'google-client-secret'
export const GOOGLE_ALLOWED_HD_DOMAINS = 'example.com,example.jp'
export const EMAIL_HASH_PEPPER_V1 = 'pepper-v1-secret-32-bytes-long!!'
export const CURRENT_EMAIL_HASH_PEPPER_VERSION = '1'
export const GITHUB_ID = '123456'
export const GITHUB_LOGIN = 'octocat'
export const USER_ID = 'user-id-uuid'
export const UPSTREAM_STATE = 'upstream-state-value'
export const CLIENT_STATE = 'client-state-value'
export const NONCE = 'nonce-value'
export const CODE_VERIFIER = 'code-verifier-value'
export const CODE_CHALLENGE = 'code-challenge-value'

export function createBindings(
  overrides: Partial<AppBindings> = {},
): AppBindings {
  return {
    DB: env.DB,
    PUBLIC_RATE_LIMITER: allowingRateLimiter,
    CLIENT_RATE_LIMITER: allowingRateLimiter,
    GITHUB_CLIENT_ID: 'github-client-id',
    GITHUB_CLIENT_SECRET: 'github-client-secret',
    GITHUB_ORG: 'example-org',
    GITHUB_CALLBACK_URL,
    OIDC_ISSUER: ISSUER,
    OIDC_SIGNING_PRIVATE_KEY: JSON.stringify(TEST_PRIVATE_JWK),
    OIDC_SIGNING_KEY_ID: TEST_KID,
    TOKEN_HASH_SECRET,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_CALLBACK_URL,
    GOOGLE_ALLOWED_HD_DOMAINS,
    EMAIL_HASH_PEPPER_V1,
    CURRENT_EMAIL_HASH_PEPPER_VERSION,
    ...overrides,
  }
}

export async function insertClient(options: { disabled?: boolean } = {}) {
  await env.DB.prepare(
    `INSERT INTO clients (client_id, created_at, disabled_at)
     VALUES (?, ?, ?)`,
  )
    .bind(CLIENT_ID, NOW, options.disabled ? NOW + 1 : null)
    .run()

  await env.DB.prepare(
    `INSERT INTO allowed_redirect_uris (client_id, redirect_uri, created_at)
     VALUES (?, ?, ?)`,
  )
    .bind(CLIENT_ID, REDIRECT_URI, NOW)
    .run()
}

export async function insertUser(userId = USER_ID) {
  await env.DB.prepare(
    `INSERT INTO users (id, created_at, updated_at)
     VALUES (?, ?, ?)`,
  )
    .bind(userId, NOW, NOW)
    .run()

  await env.DB.prepare(
    `INSERT INTO github_identities
       (github_id, user_id, github_login, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?)`,
  )
    .bind(GITHUB_ID, userId, GITHUB_LOGIN, NOW, NOW)
    .run()

  return userId
}

function currentTime(): number {
  return Math.floor(Date.now() / 1000)
}

export async function insertAuthCode(
  codeHash: string,
  options: {
    userId?: string
    clientId?: string
    redirectUri?: string
    nonce?: string
    codeChallenge?: string
    createdAt?: number
    expiresAt?: number
  } = {},
) {
  const createdAt = options.createdAt ?? currentTime()

  await env.DB.prepare(
    `INSERT INTO auth_codes
       (code_hash, user_id, client_id, redirect_uri, nonce,
        code_challenge, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      codeHash,
      options.userId ?? USER_ID,
      options.clientId ?? CLIENT_ID,
      options.redirectUri ?? REDIRECT_URI,
      options.nonce ?? NONCE,
      options.codeChallenge ?? CODE_CHALLENGE,
      createdAt,
      options.expiresAt ?? createdAt + 2 * 60,
    )
    .run()
}

export async function insertAccessToken(
  tokenHash: string,
  options: {
    userId?: string
    clientId?: string
    createdAt?: number
    expiresAt?: number
  } = {},
) {
  const createdAt = options.createdAt ?? currentTime()

  await env.DB.prepare(
    `INSERT INTO access_tokens
       (token_hash, user_id, client_id, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?)`,
  )
    .bind(
      tokenHash,
      options.userId ?? USER_ID,
      options.clientId ?? CLIENT_ID,
      createdAt,
      options.expiresAt ?? createdAt + 15 * 60,
    )
    .run()
}

export async function insertRefreshToken(
  tokenHash: string,
  options: {
    userId?: string
    clientId?: string
    createdAt?: number
    expiresAt?: number
    revokedAt?: number | null
  } = {},
) {
  const createdAt = options.createdAt ?? currentTime()

  await env.DB.prepare(
    `INSERT INTO refresh_tokens
       (token_hash, user_id, client_id, created_at, expires_at, revoked_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      tokenHash,
      options.userId ?? USER_ID,
      options.clientId ?? CLIENT_ID,
      createdAt,
      options.expiresAt ?? createdAt + 30 * 24 * 60 * 60,
      options.revokedAt ?? null,
    )
    .run()
}

export async function countRows(table: string): Promise<number> {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS count FROM ${table}`,
  ).first<{ count: number }>()

  return row?.count ?? 0
}
