const REQUIRED_STRING_BINDINGS = [
  'GITHUB_CLIENT_ID',
  'GITHUB_CLIENT_SECRET',
  'GITHUB_ORG',
  'GITHUB_CALLBACK_URL',
  'SESSION_SECRET',
] as const

const HTTP_CALLBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]'])

type RequiredStringBinding = (typeof REQUIRED_STRING_BINDINGS)[number]

export interface AppBindings {
  DB: D1Database
  PUBLIC_RATE_LIMITER: RateLimit
  CLIENT_RATE_LIMITER: RateLimit
  GITHUB_CLIENT_ID?: string
  GITHUB_CLIENT_SECRET?: string
  GITHUB_ORG?: string
  GITHUB_CALLBACK_URL?: string
  SESSION_SECRET?: string
}

export interface AuthServerConfig {
  db: D1Database
  githubClientId: string
  githubClientSecret: string
  githubOrg: string
  githubCallbackUrl: URL
  sessionSecret: string
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

  return {
    db: getDatabase(bindings.DB),
    githubClientId: getRequiredString(bindings, 'GITHUB_CLIENT_ID'),
    githubClientSecret: getRequiredString(bindings, 'GITHUB_CLIENT_SECRET'),
    githubOrg: getRequiredString(bindings, 'GITHUB_ORG'),
    githubCallbackUrl: getCallbackUrl(githubCallbackUrlValue),
    sessionSecret: getRequiredString(bindings, 'SESSION_SECRET'),
  }
}
