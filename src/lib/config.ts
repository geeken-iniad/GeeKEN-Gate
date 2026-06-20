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
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'GOOGLE_CALLBACK_URL',
  'GOOGLE_ALLOWED_HD_DOMAINS',
  'EMAIL_HASH_PEPPER_V1',
  'CURRENT_EMAIL_HASH_PEPPER_VERSION',
] as const

const HTTP_LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]'])
const MINIMUM_TOKEN_HASH_SECRET_BYTES = 32
const KNOWN_EMAIL_PEPPER_VERSIONS = [1, 2, 3] as const
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
  GOOGLE_CLIENT_ID?: string
  GOOGLE_CLIENT_SECRET?: string
  GOOGLE_CALLBACK_URL?: string
  GOOGLE_ALLOWED_HD_DOMAINS?: string
  EMAIL_HASH_PEPPER_V1?: string
  EMAIL_HASH_PEPPER_V2?: string
  EMAIL_HASH_PEPPER_V3?: string
  CURRENT_EMAIL_HASH_PEPPER_VERSION?: string
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
  googleClientId: string
  googleClientSecret: string
  googleCallbackUrl: URL
  googleAllowedHdDomains: string[]
  emailHashPeppers: Map<number, string>
  currentEmailHashPepperVersion: number
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

function getCallbackUrl(value: string, bindingName: string): URL {
  let callbackUrl: URL

  try {
    callbackUrl = new URL(value)
  } catch {
    throw new Error(`Invalid environment binding: ${bindingName}`)
  }

  const isLocalHttpCallback =
    callbackUrl.protocol === 'http:' &&
    HTTP_LOCAL_HOSTNAMES.has(callbackUrl.hostname)

  if (callbackUrl.protocol !== 'https:' && !isLocalHttpCallback) {
    throw new Error(`Invalid environment binding: ${bindingName}`)
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

function getGoogleAllowedHdDomains(value: string): string[] {
  const domains = value
    .split(',')
    .map((domain) => domain.trim().toLowerCase())
    .filter((domain) => domain.length > 0)

  if (domains.length === 0) {
    throw new Error(
      'Invalid environment binding: GOOGLE_ALLOWED_HD_DOMAINS must contain at least one domain',
    )
  }

  return domains
}

function getEmailHashPeppers(bindings: AppBindings): Map<number, string> {
  const peppers = new Map<number, string>()

  for (const version of KNOWN_EMAIL_PEPPER_VERSIONS) {
    const value = bindings[`EMAIL_HASH_PEPPER_V${version}` as keyof AppBindings]

    if (typeof value === 'string' && value.trim().length > 0) {
      peppers.set(version, value)
    }
  }

  return peppers
}

function getCurrentEmailHashPepperVersion(bindings: AppBindings): number {
  const raw = getRequiredString(bindings, 'CURRENT_EMAIL_HASH_PEPPER_VERSION')
  const version = Number.parseInt(raw, 10)

  if (!Number.isInteger(version) || version <= 0) {
    throw new Error(
      'Invalid environment binding: CURRENT_EMAIL_HASH_PEPPER_VERSION must be a positive integer',
    )
  }

  const pepperBindingName = `EMAIL_HASH_PEPPER_V${version}` as keyof AppBindings
  const pepper = bindings[pepperBindingName]

  if (typeof pepper !== 'string' || pepper.trim().length === 0) {
    throw new Error(
      `Missing or empty environment binding: ${String(pepperBindingName)}`,
    )
  }

  return version
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
  const googleCallbackUrlValue = getRequiredString(
    bindings,
    'GOOGLE_CALLBACK_URL',
  )
  const signing = await getSigningKey(bindings)
  const emailHashPeppers = getEmailHashPeppers(bindings)

  return {
    db: getDatabase(bindings.DB),
    githubClientId: getRequiredString(bindings, 'GITHUB_CLIENT_ID'),
    githubClientSecret: getRequiredString(bindings, 'GITHUB_CLIENT_SECRET'),
    githubOrg: getRequiredString(bindings, 'GITHUB_ORG'),
    githubCallbackUrl: getCallbackUrl(
      githubCallbackUrlValue,
      'GITHUB_CALLBACK_URL',
    ),
    tokenHashSecret: getTokenHashSecret(bindings),
    issuer: getIssuer(getRequiredString(bindings, 'OIDC_ISSUER')),
    signingKey: signing.privateKey,
    keyId: getRequiredString(bindings, 'OIDC_SIGNING_KEY_ID'),
    publicJwk: signing.publicJwk,
    googleClientId: getRequiredString(bindings, 'GOOGLE_CLIENT_ID'),
    googleClientSecret: getRequiredString(bindings, 'GOOGLE_CLIENT_SECRET'),
    googleCallbackUrl: getCallbackUrl(
      googleCallbackUrlValue,
      'GOOGLE_CALLBACK_URL',
    ),
    googleAllowedHdDomains: getGoogleAllowedHdDomains(
      getRequiredString(bindings, 'GOOGLE_ALLOWED_HD_DOMAINS'),
    ),
    emailHashPeppers,
    currentEmailHashPepperVersion: getCurrentEmailHashPepperVersion(bindings),
  }
}
