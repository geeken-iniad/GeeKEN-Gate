import type { PrivateJwk } from './oidc'

const REQUIRED_STRING_BINDINGS = [
  'GITHUB_CLIENT_ID',
  'GITHUB_CLIENT_SECRET',
  'GITHUB_ORG',
  'GITHUB_CALLBACK_URL',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'GOOGLE_CALLBACK_URL',
  'GOOGLE_ALLOWED_HD',
  'SESSION_SECRET',
  'OIDC_ISSUER',
  'OIDC_PRIVATE_JWK',
] as const

const HTTP_CALLBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]'])
const MINIMUM_SESSION_SECRET_BYTES = 32
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
  GOOGLE_CLIENT_ID?: string
  GOOGLE_CLIENT_SECRET?: string
  GOOGLE_CALLBACK_URL?: string
  GOOGLE_ALLOWED_HD?: string
  SESSION_SECRET?: string
  OIDC_ISSUER?: string
  OIDC_PRIVATE_JWK?: string
}

export interface AuthServerConfig {
  db: D1Database
  githubClientId: string
  githubClientSecret: string
  githubOrg: string
  githubCallbackUrl: URL
  googleClientId: string
  googleClientSecret: string
  googleCallbackUrl: URL
  googleAllowedHostedDomains: string[]
  sessionSecret: string
  oidcIssuer: URL
  oidcPrivateJwk: PrivateJwk & { kid: string }
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
    HTTP_CALLBACK_HOSTNAMES.has(callbackUrl.hostname)

  if (callbackUrl.protocol !== 'https:' && !isLocalHttpCallback) {
    throw new Error('Invalid environment binding: GITHUB_CALLBACK_URL')
  }

  return callbackUrl
}

function getSessionSecret(bindings: AppBindings): string {
  const sessionSecret = getRequiredString(bindings, 'SESSION_SECRET')

  if (
    textEncoder.encode(sessionSecret).byteLength <
    MINIMUM_SESSION_SECRET_BYTES
  ) {
    throw new Error(
      `Invalid environment binding: SESSION_SECRET must be at least ${MINIMUM_SESSION_SECRET_BYTES} UTF-8 bytes`,
    )
  }

  return sessionSecret
}

function getHttpsOrLoopbackUrl(value: string, bindingName: string): URL {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new Error(`Invalid environment binding: ${bindingName}`)
  }
  const isLocalHttp = url.protocol === 'http:' && HTTP_CALLBACK_HOSTNAMES.has(url.hostname)
  if (url.protocol !== 'https:' && !isLocalHttp) {
    throw new Error(`Invalid environment binding: ${bindingName}`)
  }
  return url
}

function getAllowedHostedDomains(value: string): string[] {
  const domains = value.split(',').map((domain) => domain.trim().toLowerCase())
  if (domains.length === 0 || domains.some((domain) => domain.length === 0)) {
    throw new Error('Invalid environment binding: GOOGLE_ALLOWED_HD')
  }
  return domains
}

function getOidcPrivateJwk(value: string): PrivateJwk & { kid: string } {
  let jwk: PrivateJwk & { kid?: string }
  try {
    jwk = JSON.parse(value) as PrivateJwk & { kid?: string }
  } catch {
    throw new Error('Invalid environment binding: OIDC_PRIVATE_JWK')
  }
  if (
    jwk.kty !== 'EC' ||
    jwk.crv !== 'P-256' ||
    typeof jwk.x !== 'string' ||
    typeof jwk.y !== 'string' ||
    typeof jwk.d !== 'string' ||
    typeof jwk.kid !== 'string' ||
    jwk.kid.trim().length === 0
  ) {
    throw new Error('Invalid environment binding: OIDC_PRIVATE_JWK')
  }
  return jwk as PrivateJwk & { kid: string }
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

export function loadAuthServerConfig(
  bindings: AppBindings,
): AuthServerConfig {
  const githubCallbackUrlValue = getRequiredString(
    bindings,
    'GITHUB_CALLBACK_URL',
  )
  const googleCallbackUrlValue = getRequiredString(
    bindings,
    'GOOGLE_CALLBACK_URL',
  )
  const issuerValue = getRequiredString(bindings, 'OIDC_ISSUER')

  return {
    db: getDatabase(bindings.DB),
    githubClientId: getRequiredString(bindings, 'GITHUB_CLIENT_ID'),
    githubClientSecret: getRequiredString(bindings, 'GITHUB_CLIENT_SECRET'),
    githubOrg: getRequiredString(bindings, 'GITHUB_ORG'),
    githubCallbackUrl: getCallbackUrl(githubCallbackUrlValue),
    googleClientId: getRequiredString(bindings, 'GOOGLE_CLIENT_ID'),
    googleClientSecret: getRequiredString(bindings, 'GOOGLE_CLIENT_SECRET'),
    googleCallbackUrl: getHttpsOrLoopbackUrl(googleCallbackUrlValue, 'GOOGLE_CALLBACK_URL'),
    googleAllowedHostedDomains: getAllowedHostedDomains(getRequiredString(bindings, 'GOOGLE_ALLOWED_HD')),
    sessionSecret: getSessionSecret(bindings),
    oidcIssuer: getHttpsOrLoopbackUrl(issuerValue, 'OIDC_ISSUER'),
    oidcPrivateJwk: getOidcPrivateJwk(
      getRequiredString(bindings, 'OIDC_PRIVATE_JWK'),
    ),
  }
}
