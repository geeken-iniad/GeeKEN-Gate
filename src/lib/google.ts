import { normalizeEmail } from './identity'

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs'
const ACCEPTED_ISSUERS = new Set(['https://accounts.google.com', 'accounts.google.com'])
const CLOCK_SKEW_SECONDS = 300
const MAX_TOKEN_AGE_SECONDS = 24 * 60 * 60
const textEncoder = new TextEncoder()

export interface GoogleAuthOptions {
  clientId: string
  clientSecret: string
  callbackUrl: URL
  allowedHostedDomains: string[]
  nonce: string
  fetch?: typeof globalThis.fetch
  now?: number
}

export interface GoogleAuthenticatedUser {
  googleSub: string
  email: string
  hostedDomain: string
  name?: string
}

export type GoogleAuthErrorCode =
  | 'google_token_exchange_failed'
  | 'google_id_token_invalid'
  | 'google_hd_missing'
  | 'google_hd_not_allowed'
  | 'google_email_missing'
  | 'google_email_not_verified'

export class GoogleAuthError extends Error {
  constructor(
    public readonly code: GoogleAuthErrorCode,
    options?: ErrorOptions,
  ) {
    super(code, options)
    this.name = 'GoogleAuthError'
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4)
  const binary = atob(padded)
  return Uint8Array.from(binary, (char) => char.charCodeAt(0))
}

function bytesToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
}

function base64UrlJson(value: string): unknown {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(value)))
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json()
  } catch (cause) {
    throw new GoogleAuthError('google_id_token_invalid', { cause })
  }
}

async function fetchJson(fetchFunction: typeof globalThis.fetch, url: string): Promise<unknown> {
  let response: Response
  try {
    response = await fetchFunction(url)
  } catch (cause) {
    throw new GoogleAuthError('google_id_token_invalid', { cause })
  }
  if (!response.ok) throw new GoogleAuthError('google_id_token_invalid')
  return readJson(response)
}

async function verifyJwtSignature(
  token: string,
  fetchFunction: typeof globalThis.fetch,
): Promise<Record<string, unknown>> {
  const parts = token.split('.')
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new GoogleAuthError('google_id_token_invalid')
  }

  let header: unknown
  let claims: unknown
  try {
    header = base64UrlJson(parts[0])
    claims = base64UrlJson(parts[1])
  } catch (cause) {
    throw new GoogleAuthError('google_id_token_invalid', { cause })
  }
  if (!isRecord(header) || header.alg !== 'RS256' || typeof header.kid !== 'string' || !isRecord(claims)) {
    throw new GoogleAuthError('google_id_token_invalid')
  }

  const jwks = await fetchJson(fetchFunction, GOOGLE_JWKS_URL)
  if (!isRecord(jwks) || !Array.isArray(jwks.keys)) {
    throw new GoogleAuthError('google_id_token_invalid')
  }
  const jwk = jwks.keys.find((key) => isRecord(key) && key.kid === header.kid)
  if (!isRecord(jwk)) throw new GoogleAuthError('google_id_token_invalid')

  let key: CryptoKey
  try {
    key = await crypto.subtle.importKey(
      'jwk',
      jwk as JsonWebKey,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    )
  } catch (cause) {
    throw new GoogleAuthError('google_id_token_invalid', { cause })
  }

  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    bytesToArrayBuffer(base64UrlToBytes(parts[2])),
    textEncoder.encode(`${parts[0]}.${parts[1]}`),
  )
  if (!valid) throw new GoogleAuthError('google_id_token_invalid')

  return claims
}

export async function verifyGoogleIdToken(
  idToken: string,
  options: Omit<GoogleAuthOptions, 'clientSecret' | 'callbackUrl'>,
): Promise<GoogleAuthenticatedUser> {
  const fetchFunction = options.fetch ?? globalThis.fetch
  const now = options.now ?? Math.floor(Date.now() / 1000)
  const claims = await verifyJwtSignature(idToken, fetchFunction)

  if (
    !ACCEPTED_ISSUERS.has(String(claims.iss)) ||
    claims.aud !== options.clientId ||
    typeof claims.exp !== 'number' ||
    claims.exp <= now ||
    typeof claims.iat !== 'number' ||
    claims.iat > now + CLOCK_SKEW_SECONDS ||
    claims.iat < now - MAX_TOKEN_AGE_SECONDS ||
    claims.nonce !== options.nonce ||
    typeof claims.sub !== 'string' ||
    claims.sub.length === 0
  ) {
    throw new GoogleAuthError('google_id_token_invalid')
  }

  if (typeof claims.email !== 'string' || normalizeEmail(claims.email).length === 0) {
    throw new GoogleAuthError('google_email_missing')
  }
  if (claims.email_verified !== true) {
    throw new GoogleAuthError('google_email_not_verified')
  }
  if (typeof claims.hd !== 'string' || claims.hd.trim().length === 0) {
    throw new GoogleAuthError('google_hd_missing')
  }
  const hostedDomain = claims.hd.trim().toLowerCase()
  if (!options.allowedHostedDomains.includes(hostedDomain)) {
    throw new GoogleAuthError('google_hd_not_allowed')
  }

  return {
    googleSub: claims.sub,
    email: normalizeEmail(claims.email),
    hostedDomain,
    name: typeof claims.name === 'string' && claims.name.length > 0 ? claims.name : undefined,
  }
}

export async function authenticateGoogleUser(
  code: string,
  options: GoogleAuthOptions,
): Promise<GoogleAuthenticatedUser> {
  const fetchFunction = options.fetch ?? globalThis.fetch
  let response: Response
  try {
    response = await fetchFunction(GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: options.clientId,
        client_secret: options.clientSecret,
        redirect_uri: options.callbackUrl.href,
      }).toString(),
    })
  } catch (cause) {
    throw new GoogleAuthError('google_token_exchange_failed', { cause })
  }
  if (!response.ok) throw new GoogleAuthError('google_token_exchange_failed')

  const payload = await readJson(response)
  if (!isRecord(payload) || typeof payload.id_token !== 'string' || payload.id_token.length === 0) {
    throw new GoogleAuthError('google_id_token_invalid')
  }
  return verifyGoogleIdToken(payload.id_token, options)
}
