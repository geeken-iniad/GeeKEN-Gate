const TOKEN_BYTE_LENGTH = 32
const SHA256_BYTE_LENGTH = 32
const CODE_VERIFIER_BYTE_LENGTH = 32
const textEncoder = new TextEncoder()

export type AuthTokenPurpose =
  | 'oauth-upstream-state'
  | 'auth-code'
  | 'access-token'
  | 'refresh-token'
  | 'email-allowlist'

type TimingSafeSubtleCrypto = SubtleCrypto & {
  timingSafeEqual(
    first: ArrayBuffer | ArrayBufferView,
    second: ArrayBuffer | ArrayBufferView,
  ): boolean
}

function bytesToBase64Url(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes)

  return btoa(binary)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '')
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join(
    '',
  )
}

function hexToBytes(value: string): Uint8Array | null {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    return null
  }

  const bytes = new Uint8Array(SHA256_BYTE_LENGTH)

  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }

  return bytes
}

async function sha256(value: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(value))

  return new Uint8Array(digest)
}

export function generateRandomToken(): string {
  return bytesToBase64Url(
    crypto.getRandomValues(new Uint8Array(TOKEN_BYTE_LENGTH)),
  )
}

export function generateCodeVerifier(): string {
  return bytesToBase64Url(
    crypto.getRandomValues(new Uint8Array(CODE_VERIFIER_BYTE_LENGTH)),
  )
}

export async function generateCodeChallenge(verifier: string): Promise<string> {
  return bytesToBase64Url(await sha256(verifier))
}

export async function hashAuthToken(
  value: string,
  secret: string,
  purpose: AuthTokenPurpose,
): Promise<string> {
  if (secret.length === 0) {
    throw new Error('HMAC secret must not be empty')
  }

  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    textEncoder.encode(`${purpose}\0${value}`),
  )

  return bytesToHex(new Uint8Array(signature))
}

export async function verifyHashedToken(
  value: string,
  expectedHash: string,
  secret: string,
  purpose: AuthTokenPurpose,
): Promise<boolean> {
  const actualHash = await hashAuthToken(value, secret, purpose)
  const actualBytes = hexToBytes(actualHash)
  const expectedBytes = hexToBytes(expectedHash)

  if (actualBytes === null || expectedBytes === null) {
    return false
  }

  const subtleCrypto = crypto.subtle as TimingSafeSubtleCrypto
  return subtleCrypto.timingSafeEqual(actualBytes, expectedBytes)
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase()
}

export async function hashEmailAddress(
  email: string,
  pepper: string,
): Promise<string> {
  if (pepper.length === 0) {
    throw new Error('Email HMAC pepper must not be empty')
  }

  return hashAuthToken(email, pepper, 'email-allowlist')
}
