import { bytesToBase64Url, sha256 } from './crypto'

const textEncoder = new TextEncoder()

export interface PrivateJwk {
  kty: string
  crv?: string
  x?: string
  y?: string
  d?: string
  kid?: string
  alg?: string
  key_ops?: string[]
  ext?: boolean
}

export interface IdTokenClaims {
  iss: string
  sub: string
  aud: string
  exp: number
  iat: number
  auth_time: number
  nonce?: string
}

function base64UrlJson(value: unknown): string {
  return bytesToBase64Url(textEncoder.encode(JSON.stringify(value)))
}

function derToJose(signature: ArrayBuffer): string {
  const bytes = new Uint8Array(signature)
  if (bytes.length === 64) return bytesToBase64Url(bytes)
  let offset = 2
  const rLength = bytes[offset + 1]
  const r = bytes.slice(offset + 2, offset + 2 + rLength)
  offset += 2 + rLength
  const sLength = bytes[offset + 1]
  const s = bytes.slice(offset + 2, offset + 2 + sLength)
  const out = new Uint8Array(64)
  out.set(r.slice(Math.max(0, r.length - 32)), Math.max(0, 32 - r.length))
  out.set(s.slice(Math.max(0, s.length - 32)), 32 + Math.max(0, 32 - s.length))
  return bytesToBase64Url(out)
}

export function publicJwkFromPrivate(jwk: PrivateJwk): JsonWebKey & { kid?: string } {
  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    kid: jwk.kid,
    alg: 'ES256',
    use: 'sig',
    key_ops: ['verify'],
  }
}

export async function signIdToken(
  claims: IdTokenClaims,
  privateJwk: PrivateJwk,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    'jwk',
    privateJwk as JsonWebKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  )
  const header = { alg: 'ES256', typ: 'JWT', kid: privateJwk.kid }
  const signingInput = `${base64UrlJson(header)}.${base64UrlJson(claims)}`
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    textEncoder.encode(signingInput),
  )

  return `${signingInput}.${derToJose(signature)}`
}

export async function verifyPkceChallenge(
  verifier: string,
  challenge: string,
  method: string,
): Promise<boolean> {
  if (method === 'plain') return verifier === challenge
  if (method !== 'S256') return false
  return bytesToBase64Url(await sha256(verifier)) === challenge
}
