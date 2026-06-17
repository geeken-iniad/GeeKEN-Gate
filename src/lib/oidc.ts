const textEncoder = new TextEncoder()

export interface DiscoveryMetadata {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  jwks_uri: string
  response_types_supported: string[]
  grant_types_supported: string[]
  subject_types_supported: string[]
  id_token_signing_alg_values_supported: string[]
  scopes_supported: string[]
  token_endpoint_auth_methods_supported: string[]
  code_challenge_methods_supported: string[]
}

export function buildDiscoveryMetadata(issuer: URL): DiscoveryMetadata {
  const issuerUrl = issuer.href.replace(/\/+$/, '')

  return {
    issuer: issuerUrl,
    authorization_endpoint: `${issuerUrl}/authorize`,
    token_endpoint: `${issuerUrl}/token`,
    userinfo_endpoint: `${issuerUrl}/userinfo`,
    jwks_uri: `${issuerUrl}/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
  }
}

export function buildJwks(publicJwk: JsonWebKey): { keys: JsonWebKey[] } {
  return { keys: [publicJwk] }
}

function bytesToBase64Url(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes)

  return btoa(binary)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '')
}

function base64UrlEncode(input: string): string {
  return bytesToBase64Url(textEncoder.encode(input))
}

export async function importRsaPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  )
}

export function getPublicJwk(privateJwk: JsonWebKey, kid: string): JsonWebKey {
  if (
    privateJwk.kty !== 'RSA' ||
    typeof privateJwk.n !== 'string' ||
    typeof privateJwk.e !== 'string'
  ) {
    throw new Error('Invalid RSA private JWK')
  }

  return {
    kty: 'RSA',
    n: privateJwk.n,
    e: privateJwk.e,
    kid,
    alg: 'RS256',
    use: 'sig',
  } as JsonWebKey
}

export interface IdTokenClaims {
  iss: string
  sub: string
  aud: string
  exp: number
  iat: number
  nonce?: string
}

export async function signIdToken(
  claims: IdTokenClaims,
  privateKey: CryptoKey,
  kid: string,
): Promise<string> {
  const header = { alg: 'RS256', typ: 'JWT', kid }
  const encodedHeader = base64UrlEncode(JSON.stringify(header))
  const encodedPayload = base64UrlEncode(JSON.stringify(claims))
  const signingInput = `${encodedHeader}.${encodedPayload}`
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    textEncoder.encode(signingInput),
  )
  const encodedSignature = bytesToBase64Url(new Uint8Array(signature))

  return `${signingInput}.${encodedSignature}`
}

export async function verifyPKCE(
  codeVerifier: string,
  codeChallenge: string,
): Promise<boolean> {
  const challengeBytes = await crypto.subtle.digest(
    'SHA-256',
    textEncoder.encode(codeVerifier),
  )
  const computedChallenge = bytesToBase64Url(new Uint8Array(challengeBytes))
  const expected = textEncoder.encode(codeChallenge)
  const actual = textEncoder.encode(computedChallenge)

  if (expected.byteLength !== actual.byteLength) {
    return false
  }

  const subtleCrypto = crypto.subtle as unknown as {
    timingSafeEqual(
      first: ArrayBuffer | ArrayBufferView,
      second: ArrayBuffer | ArrayBufferView,
    ): boolean
  }

  return subtleCrypto.timingSafeEqual(expected, actual)
}
