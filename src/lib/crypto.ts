const TOKEN_BYTE_LENGTH = 32
const SHA256_BYTE_LENGTH = 32
const textEncoder = new TextEncoder()

export type AuthTokenPurpose =
  | 'session'
  | 'oauth-state'
  | 'auth-code'
  | 'access-token'

type TimingSafeSubtleCrypto = SubtleCrypto & {
  timingSafeEqual(
    first: ArrayBuffer | ArrayBufferView,
    second: ArrayBuffer | ArrayBufferView,
  ): boolean
}

export function bytesToBase64Url(bytes: Uint8Array): string {
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

export async function sha256(value: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', textEncoder.encode(value))

  return new Uint8Array(digest)
}

export function generateRandomToken(): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(TOKEN_BYTE_LENGTH)))
}

export function generateClientSecret(): string {
  return generateRandomToken()
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

export async function hashClientSecret(clientSecret: string): Promise<string> {
  return bytesToHex(await sha256(clientSecret))
}

export async function verifyClientSecret(
  clientSecret: string,
  expectedHash: string,
): Promise<boolean> {
  const actualHash = await sha256(clientSecret)
  const parsedExpectedHash = hexToBytes(expectedHash)
  const comparisonHash =
    parsedExpectedHash ?? new Uint8Array(SHA256_BYTE_LENGTH)
  const subtleCrypto = crypto.subtle as TimingSafeSubtleCrypto
  const matches = subtleCrypto.timingSafeEqual(actualHash, comparisonHash)

  return parsedExpectedHash !== null && matches
}
