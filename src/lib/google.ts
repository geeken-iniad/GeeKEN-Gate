const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs'
const GOOGLE_ACCEPTED_ISSUERS = new Set([
  'https://accounts.google.com',
  'accounts.google.com',
])
const GOOGLE_CANONICAL_ISSUER = 'https://accounts.google.com'
const CLOCK_SKEW_SECONDS = 60

export function canonicalizeGoogleIssuer(issuer: string): string {
  if (!GOOGLE_ACCEPTED_ISSUERS.has(issuer)) {
    throw new GoogleAuthError('invalid_issuer')
  }

  return GOOGLE_CANONICAL_ISSUER
}

export interface GoogleAuthOptions {
  clientId: string
  clientSecret: string
  callbackUrl: URL
  allowedHdDomains: string[]
  fetch?: typeof globalThis.fetch
}

export interface GoogleAuthenticatedUser {
  issuer: string
  sub: string
  email: string
  hd: string
}

export type GoogleAuthErrorCode =
  | 'token_exchange_failed'
  | 'jwks_fetch_failed'
  | 'invalid_id_token'
  | 'invalid_signature'
  | 'invalid_issuer'
  | 'invalid_audience'
  | 'expired_id_token'
  | 'email_not_verified'
  | 'invalid_hosted_domain'

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
  const padding = '='.repeat((4 - (value.length % 4)) % 4)
  const base64 = value.replaceAll('-', '+').replaceAll('_', '/') + padding
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }

  return bytes
}

interface ParsedJwt {
  header: unknown
  payload: unknown
  signature: Uint8Array
  signingInput: string
}

function parseJwt(token: string): ParsedJwt | null {
  const parts = token.split('.')

  if (parts.length !== 3) {
    return null
  }

  try {
    const textDecoder = new TextDecoder()
    const header = JSON.parse(textDecoder.decode(base64UrlToBytes(parts[0])))
    const payload = JSON.parse(textDecoder.decode(base64UrlToBytes(parts[1])))
    const signature = base64UrlToBytes(parts[2])

    return {
      header,
      payload,
      signature,
      signingInput: `${parts[0]}.${parts[1]}`,
    }
  } catch {
    return null
  }
}

async function fetchJwks(
  fetchFunction: typeof globalThis.fetch,
): Promise<unknown> {
  let response: Response

  try {
    response = await fetchFunction(GOOGLE_JWKS_URL)
  } catch (cause) {
    throw new GoogleAuthError('jwks_fetch_failed', { cause })
  }

  if (!response.ok) {
    throw new GoogleAuthError('jwks_fetch_failed')
  }

  try {
    return await response.json()
  } catch (cause) {
    throw new GoogleAuthError('jwks_fetch_failed', { cause })
  }
}

async function importSigningKey(
  jwks: unknown,
  kid: string,
): Promise<CryptoKey> {
  if (!isRecord(jwks) || !Array.isArray(jwks.keys)) {
    throw new GoogleAuthError('invalid_signature')
  }

  const key = jwks.keys.find(
    (entry: unknown) =>
      isRecord(entry) &&
      entry.kid === kid &&
      entry.kty === 'RSA' &&
      entry.alg === 'RS256' &&
      typeof entry.n === 'string' &&
      typeof entry.e === 'string',
  )

  if (!isRecord(key)) {
    throw new GoogleAuthError('invalid_signature')
  }

  return crypto.subtle.importKey(
    'jwk',
    key,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  )
}

async function verifySignature(
  idToken: string,
  parsedJwt: ParsedJwt,
  fetchFunction: typeof globalThis.fetch,
): Promise<void> {
  if (
    !isRecord(parsedJwt.header) ||
    parsedJwt.header.alg !== 'RS256' ||
    typeof parsedJwt.header.kid !== 'string'
  ) {
    throw new GoogleAuthError('invalid_signature')
  }

  const jwks = await fetchJwks(fetchFunction)
  const publicKey = await importSigningKey(jwks, parsedJwt.header.kid)
  const signatureValid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    publicKey,
    parsedJwt.signature as unknown as ArrayBuffer,
    new TextEncoder().encode(parsedJwt.signingInput),
  )

  if (!signatureValid) {
    throw new GoogleAuthError('invalid_signature')
  }
}

function validateClaims(
  payload: unknown,
  clientId: string,
  allowedHdDomains: string[],
  nowSeconds: number,
): GoogleAuthenticatedUser {
  if (!isRecord(payload)) {
    throw new GoogleAuthError('invalid_id_token')
  }

  const issuer = payload.iss
  const sub = payload.sub
  const audience = payload.aud
  const expiresAt = payload.exp
  const issuedAt = payload.iat
  const emailVerified = payload.email_verified
  const email = payload.email
  const hostedDomain = payload.hd

  if (typeof issuer !== 'string' || !GOOGLE_ACCEPTED_ISSUERS.has(issuer)) {
    throw new GoogleAuthError('invalid_issuer')
  }

  if (typeof sub !== 'string' || sub.length === 0) {
    throw new GoogleAuthError('invalid_id_token')
  }

  if (audience !== clientId) {
    throw new GoogleAuthError('invalid_audience')
  }

  if (
    typeof expiresAt !== 'number' ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= nowSeconds - CLOCK_SKEW_SECONDS
  ) {
    throw new GoogleAuthError('expired_id_token')
  }

  if (
    typeof issuedAt !== 'number' ||
    !Number.isFinite(issuedAt) ||
    issuedAt > nowSeconds + CLOCK_SKEW_SECONDS
  ) {
    throw new GoogleAuthError('expired_id_token')
  }

  if (emailVerified !== true) {
    throw new GoogleAuthError('email_not_verified')
  }

  if (
    typeof hostedDomain !== 'string' ||
    !allowedHdDomains.includes(hostedDomain.toLowerCase())
  ) {
    throw new GoogleAuthError('invalid_hosted_domain')
  }

  if (typeof email !== 'string' || email.length === 0) {
    throw new GoogleAuthError('invalid_id_token')
  }

  return {
    issuer: GOOGLE_CANONICAL_ISSUER,
    sub,
    email,
    hd: hostedDomain.toLowerCase(),
  }
}

async function exchangeCode(
  code: string,
  options: GoogleAuthOptions,
): Promise<string> {
  const fetchFunction = options.fetch ?? globalThis.fetch
  let response: Response

  try {
    response = await fetchFunction(GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: options.clientId,
        client_secret: options.clientSecret,
        redirect_uri: options.callbackUrl.href,
      }).toString(),
    })
  } catch (cause) {
    throw new GoogleAuthError('token_exchange_failed', { cause })
  }

  let payload: unknown

  try {
    payload = await response.json()
  } catch (cause) {
    throw new GoogleAuthError('token_exchange_failed', { cause })
  }

  if (!isRecord(payload) || typeof payload.id_token !== 'string') {
    throw new GoogleAuthError('token_exchange_failed')
  }

  return payload.id_token
}

export async function authenticateGoogleUser(
  code: string,
  options: GoogleAuthOptions,
): Promise<GoogleAuthenticatedUser> {
  const fetchFunction = options.fetch ?? globalThis.fetch
  const idToken = await exchangeCode(code, options)
  const parsedJwt = parseJwt(idToken)

  if (parsedJwt === null) {
    throw new GoogleAuthError('invalid_id_token')
  }

  await verifySignature(idToken, parsedJwt, fetchFunction)

  const nowSeconds = Math.floor(Date.now() / 1000)

  return validateClaims(
    parsedJwt.payload,
    options.clientId,
    options.allowedHdDomains,
    nowSeconds,
  )
}
