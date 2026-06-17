import { getPublicJwk, importRsaPrivateKey } from './oidc'

const REQUIRED_STRING_BINDINGS = [
  'GITHUB_CLIENT_ID',
  'GITHUB_CLIENT_SECRET',
  'GITHUB_ORG',
  'GITHUB_CALLBACK_URL',
  'OIDC_ISSUER',
  'OIDC_SIGNING_PRIVATE_KEY',
  'OIDC_SIGNING_KEY_ID',
  'TOKEN_HASH_SECRET',
] as const

const HTTP_LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]'])
const MINIMUM_TOKEN_HASH_SECRET_BYTES = 32
const textEncoder = new TextEncoder()

type RequiredStringBinding = (typeof REQUIRED_STRING_BINDINGS)[number]

export interface AppBindings {
  DB: D1Database
  PUBLIC_RATE_LIMITER: RateLimit
  CLIENT_RATE_LIMITER: RateLimit
  GITHUB_CLIENT_ID?: string
  GITHUB_CLIENT_SECRET?: string
  GITHUB_ORG?: string
  GITHUB_CALLBACK_URL?: string
  OIDC_ISSUER?: string
  OIDC_SIGNING_PRIVATE_KEY?: string
  OIDC_SIGNING_KEY_ID?: string
  TOKEN_HASH_SECRET?: string
}

export interface AuthServerConfig {
  db: D1Database
  githubClientId: string
  githubClientSecret: string
  githubOrg: string
  githubCallbackUrl: URL
  tokenHashSecret: string
  issuer: URL
  signingKey: CryptoKey
  keyId: string
  publicJwk: JsonWebKey
}

function getRequiredString(
  bindings: AppBindings,
  name: RequiredStringBinding,
): string {
  const value = bindings[name]

  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`Missing or empty environment binding: ${name}`)
  }

  return value
}

function getCallbackUrl(value: string): URL {
  let callbackUrl: URL

  try {
    callbackUrl = new URL(value)
  } catch {
    throw new Error('Invalid environment binding: GITHUB_CALLBACK_URL')
  }

  const isLocalHttpCallback =
    callbackUrl.protocol === 'http:' &&
    HTTP_LOCAL_HOSTNAMES.has(callbackUrl.hostname)

  if (callbackUrl.protocol !== 'https:' && !isLocalHttpCallback) {
    throw new Error('Invalid environment binding: GITHUB_CALLBACK_URL')
  }

  return callbackUrl
}

function getIssuer(value: string): URL {
  let issuer: URL

  try {
    issuer = new URL(value)
  } catch {
    throw new Error('Invalid environment binding: OIDC_ISSUER')
  }

  const isLocalHttpIssuer =
    issuer.protocol === 'http:' && HTTP_LOCAL_HOSTNAMES.has(issuer.hostname)

  if (issuer.protocol !== 'https:' && !isLocalHttpIssuer) {
    throw new Error('Invalid environment binding: OIDC_ISSUER')
  }

  if (issuer.search || issuer.hash) {
    throw new Error('Invalid environment binding: OIDC_ISSUER')
  }

  return issuer
}

function getTokenHashSecret(bindings: AppBindings): string {
  const secret = getRequiredString(bindings, 'TOKEN_HASH_SECRET')

  if (
    textEncoder.encode(secret).byteLength < MINIMUM_TOKEN_HASH_SECRET_BYTES
  ) {
    throw new Error(
      `Invalid environment binding: TOKEN_HASH_SECRET must be at least ${MINIMUM_TOKEN_HASH_SECRET_BYTES} UTF-8 bytes`,
    )
  }

  return secret
}

async function getSigningKey(
  bindings: AppBindings,
): Promise<{ privateKey: CryptoKey; publicJwk: JsonWebKey }> {
  const raw = getRequiredString(bindings, 'OIDC_SIGNING_PRIVATE_KEY')
  let jwk: JsonWebKey

  try {
    jwk = JSON.parse(raw)
  } catch {
    throw new Error('Invalid environment binding: OIDC_SIGNING_PRIVATE_KEY')
  }

  const kid = getRequiredString(bindings, 'OIDC_SIGNING_KEY_ID')
  let privateKey: CryptoKey

  try {
    privateKey = await importRsaPrivateKey(jwk)
  } catch {
    throw new Error('Invalid environment binding: OIDC_SIGNING_PRIVATE_KEY')
  }

  const publicJwk = getPublicJwk(jwk, kid)

  return { privateKey, publicJwk }
}

function getDatabase(value: unknown): D1Database {
  if (
    typeof value !== 'object' ||
    value === null ||
    typeof (value as Partial<D1Database>).prepare !== 'function' ||
    typeof (value as Partial<D1Database>).batch !== 'function'
  ) {
    throw new Error('Missing or invalid environment binding: DB')
  }

  return value as D1Database
}

export async function loadAuthServerConfig(
  bindings: AppBindings,
): Promise<AuthServerConfig> {
  const githubCallbackUrlValue = getRequiredString(
    bindings,
    'GITHUB_CALLBACK_URL',
  )
  const signing = await getSigningKey(bindings)

  return {
    db: getDatabase(bindings.DB),
    githubClientId: getRequiredString(bindings, 'GITHUB_CLIENT_ID'),
    githubClientSecret: getRequiredString(bindings, 'GITHUB_CLIENT_SECRET'),
    githubOrg: getRequiredString(bindings, 'GITHUB_ORG'),
    githubCallbackUrl: getCallbackUrl(githubCallbackUrlValue),
    tokenHashSecret: getTokenHashSecret(bindings),
    issuer: getIssuer(getRequiredString(bindings, 'OIDC_ISSUER')),
    signingKey: signing.privateKey,
    keyId: getRequiredString(bindings, 'OIDC_SIGNING_KEY_ID'),
    publicJwk: signing.publicJwk,
  }
}
