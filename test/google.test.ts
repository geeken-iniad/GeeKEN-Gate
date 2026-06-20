import { describe, expect, it, vi } from 'vitest'

import {
  authenticateGoogleUser,
  GoogleAuthError,
  type GoogleAuthOptions,
} from '../src/lib/google'

const CLIENT_ID = 'google-client-id'
const CLIENT_SECRET = 'google-client-secret'
const CALLBACK_URL = new URL('https://auth.example.com/callback/google')
const ALLOWED_HD_DOMAINS = ['example.com']

function createOptions(fetchMock: ReturnType<typeof vi.fn>): GoogleAuthOptions {
  return {
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    callbackUrl: CALLBACK_URL,
    allowedHdDomains: ALLOWED_HD_DOMAINS,
    fetch: fetchMock as typeof globalThis.fetch,
  }
}

function base64Url(input: string): string {
  return btoa(input)
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '')
}

async function createKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )
}

async function exportJwk(key: CryptoKey): Promise<JsonWebKey & { kid: string }> {
  return crypto.subtle.exportKey('jwk', key) as Promise<JsonWebKey & { kid: string }>
}

async function signIdToken(
  privateKey: CryptoKey,
  kid: string,
  payload: Record<string, unknown>,
): Promise<string> {
  const header = { alg: 'RS256', typ: 'JWT', kid }
  const encodedHeader = base64Url(JSON.stringify(header))
  const encodedPayload = base64Url(JSON.stringify(payload))
  const signingInput = `${encodedHeader}.${encodedPayload}`
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    new TextEncoder().encode(signingInput),
  )
  const encodedSignature = base64Url(
    String.fromCharCode(...new Uint8Array(signature)),
  )

  return `${signingInput}.${encodedSignature}`
}

function createTokenResponse(idToken: string): Response {
  return Response.json({
    access_token: 'google-access-token',
    token_type: 'Bearer',
    id_token: idToken,
  })
}

function createJwksResponse(publicJwk: JsonWebKey): Response {
  return Response.json({ keys: [{ ...publicJwk, use: 'sig' }] })
}

function expectGoogleError(
  promise: Promise<unknown>,
  code:
    | 'token_exchange_failed'
    | 'jwks_fetch_failed'
    | 'invalid_id_token'
    | 'invalid_signature'
    | 'invalid_issuer'
    | 'invalid_audience'
    | 'expired_id_token'
    | 'email_not_verified'
    | 'invalid_hosted_domain',
) {
  return expect(promise).rejects.toMatchObject({
    name: 'GoogleAuthError',
    message: code,
    code,
  })
}

describe('authenticateGoogleUser', () => {
  it('returns the authenticated user for a valid ID Token', async () => {
    const keyPair = await createKeyPair()
    const publicJwk = await exportJwk(keyPair.publicKey)
    publicJwk.kid = 'test-key'
    const now = Math.floor(Date.now() / 1000)
    const idToken = await signIdToken(keyPair.privateKey, 'test-key', {
      iss: 'https://accounts.google.com',
      sub: 'google-sub',
      aud: CLIENT_ID,
      exp: now + 300,
      iat: now,
      email_verified: true,
      email: 'user@example.com',
      hd: 'example.com',
    })
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse(idToken))
      .mockResolvedValueOnce(createJwksResponse(publicJwk))

    await expect(
      authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
    ).resolves.toEqual({
      issuer: 'https://accounts.google.com',
      sub: 'google-sub',
      email: 'user@example.com',
      hd: 'example.com',
    })

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://oauth2.googleapis.com/token',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'google-oauth-code',
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          redirect_uri: CALLBACK_URL.href,
        }).toString(),
      },
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://www.googleapis.com/oauth2/v3/certs',
    )
  })

  it('canonicalizes the issuer without scheme to the scheme form', async () => {
    const keyPair = await createKeyPair()
    const publicJwk = await exportJwk(keyPair.publicKey)
    publicJwk.kid = 'test-key'
    const now = Math.floor(Date.now() / 1000)
    const idToken = await signIdToken(keyPair.privateKey, 'test-key', {
      iss: 'accounts.google.com',
      sub: 'google-sub',
      aud: CLIENT_ID,
      exp: now + 300,
      iat: now,
      email_verified: true,
      email: 'user@example.com',
      hd: 'example.com',
    })
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse(idToken))
      .mockResolvedValueOnce(createJwksResponse(publicJwk))

    await expect(
      authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
    ).resolves.toMatchObject({
      issuer: 'https://accounts.google.com',
    })
  })

  it('rejects an ID Token with an invalid signature', async () => {
    const attackerKeyPair = await createKeyPair()
    const attackerPublicJwk = await exportJwk(attackerKeyPair.publicKey)
    attackerPublicJwk.kid = 'attacker-key'
    const legitimateKeyPair = await createKeyPair()
    const legitimatePublicJwk = await exportJwk(legitimateKeyPair.publicKey)
    legitimatePublicJwk.kid = 'test-key'
    const now = Math.floor(Date.now() / 1000)
    const idToken = await signIdToken(attackerKeyPair.privateKey, 'test-key', {
      iss: 'https://accounts.google.com',
      sub: 'google-sub',
      aud: CLIENT_ID,
      exp: now + 300,
      iat: now,
      email_verified: true,
      email: 'user@example.com',
      hd: 'example.com',
    })
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse(idToken))
      .mockResolvedValueOnce(createJwksResponse(legitimatePublicJwk))

    await expectGoogleError(
      authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
      'invalid_signature',
    )
  })

  it('rejects an ID Token with a disallowed issuer', async () => {
    const keyPair = await createKeyPair()
    const publicJwk = await exportJwk(keyPair.publicKey)
    publicJwk.kid = 'test-key'
    const now = Math.floor(Date.now() / 1000)
    const idToken = await signIdToken(keyPair.privateKey, 'test-key', {
      iss: 'https://evil.example',
      sub: 'google-sub',
      aud: CLIENT_ID,
      exp: now + 300,
      iat: now,
      email_verified: true,
      email: 'user@example.com',
      hd: 'example.com',
    })
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse(idToken))
      .mockResolvedValueOnce(createJwksResponse(publicJwk))

    await expectGoogleError(
      authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
      'invalid_issuer',
    )
  })

  it('rejects an ID Token with a wrong audience', async () => {
    const keyPair = await createKeyPair()
    const publicJwk = await exportJwk(keyPair.publicKey)
    publicJwk.kid = 'test-key'
    const now = Math.floor(Date.now() / 1000)
    const idToken = await signIdToken(keyPair.privateKey, 'test-key', {
      iss: 'https://accounts.google.com',
      sub: 'google-sub',
      aud: 'other-client-id',
      exp: now + 300,
      iat: now,
      email_verified: true,
      email: 'user@example.com',
      hd: 'example.com',
    })
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse(idToken))
      .mockResolvedValueOnce(createJwksResponse(publicJwk))

    await expectGoogleError(
      authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
      'invalid_audience',
    )
  })

  it('rejects an expired ID Token', async () => {
    const keyPair = await createKeyPair()
    const publicJwk = await exportJwk(keyPair.publicKey)
    publicJwk.kid = 'test-key'
    const now = Math.floor(Date.now() / 1000)
    const idToken = await signIdToken(keyPair.privateKey, 'test-key', {
      iss: 'https://accounts.google.com',
      sub: 'google-sub',
      aud: CLIENT_ID,
      exp: now - 120,
      iat: now - 600,
      email_verified: true,
      email: 'user@example.com',
      hd: 'example.com',
    })
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse(idToken))
      .mockResolvedValueOnce(createJwksResponse(publicJwk))

    await expectGoogleError(
      authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
      'expired_id_token',
    )
  })

  it('rejects an ID Token issued too far in the future', async () => {
    const keyPair = await createKeyPair()
    const publicJwk = await exportJwk(keyPair.publicKey)
    publicJwk.kid = 'test-key'
    const now = Math.floor(Date.now() / 1000)
    const idToken = await signIdToken(keyPair.privateKey, 'test-key', {
      iss: 'https://accounts.google.com',
      sub: 'google-sub',
      aud: CLIENT_ID,
      exp: now + 600,
      iat: now + 300,
      email_verified: true,
      email: 'user@example.com',
      hd: 'example.com',
    })
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse(idToken))
      .mockResolvedValueOnce(createJwksResponse(publicJwk))

    await expectGoogleError(
      authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
      'expired_id_token',
    )
  })

  it('rejects an unverified email', async () => {
    const keyPair = await createKeyPair()
    const publicJwk = await exportJwk(keyPair.publicKey)
    publicJwk.kid = 'test-key'
    const now = Math.floor(Date.now() / 1000)
    const idToken = await signIdToken(keyPair.privateKey, 'test-key', {
      iss: 'https://accounts.google.com',
      sub: 'google-sub',
      aud: CLIENT_ID,
      exp: now + 300,
      iat: now,
      email_verified: false,
      email: 'user@example.com',
      hd: 'example.com',
    })
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse(idToken))
      .mockResolvedValueOnce(createJwksResponse(publicJwk))

    await expectGoogleError(
      authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
      'email_not_verified',
    )
  })

  it('rejects a disallowed hosted domain', async () => {
    const keyPair = await createKeyPair()
    const publicJwk = await exportJwk(keyPair.publicKey)
    publicJwk.kid = 'test-key'
    const now = Math.floor(Date.now() / 1000)
    const idToken = await signIdToken(keyPair.privateKey, 'test-key', {
      iss: 'https://accounts.google.com',
      sub: 'google-sub',
      aud: CLIENT_ID,
      exp: now + 300,
      iat: now,
      email_verified: true,
      email: 'user@evil.example',
      hd: 'evil.example',
    })
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse(idToken))
      .mockResolvedValueOnce(createJwksResponse(publicJwk))

    await expectGoogleError(
      authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
      'invalid_hosted_domain',
    )
  })

  it.each([
    ['missing sub', { sub: undefined }],
    ['empty sub', { sub: '' }],
    ['numeric sub', { sub: 123456 }],
    ['null sub', { sub: null }],
    ['object sub', { sub: { id: 'google-sub' } }],
  ])(
    'rejects an ID Token with %s',
    async (_caseName, subOverride) => {
      const keyPair = await createKeyPair()
      const publicJwk = await exportJwk(keyPair.publicKey)
      publicJwk.kid = 'test-key'
      const now = Math.floor(Date.now() / 1000)
      const idToken = await signIdToken(keyPair.privateKey, 'test-key', {
        iss: 'https://accounts.google.com',
        aud: CLIENT_ID,
        exp: now + 300,
        iat: now,
        email_verified: true,
        email: 'user@example.com',
        hd: 'example.com',
        ...subOverride,
      })
      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce(createTokenResponse(idToken))
        .mockResolvedValueOnce(createJwksResponse(publicJwk))

      await expectGoogleError(
        authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
        'invalid_id_token',
      )
    },
  )

  it('classifies an unsuccessful token exchange', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(Response.json({}, { status: 400 }))

    await expectGoogleError(
      authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
      'token_exchange_failed',
    )
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('classifies a missing id_token as a token exchange failure', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(Response.json({ access_token: 'token' }))

    await expectGoogleError(
      authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
      'token_exchange_failed',
    )
  })

  it('classifies a JWKS fetch failure', async () => {
    const keyPair = await createKeyPair()
    const now = Math.floor(Date.now() / 1000)
    const idToken = await signIdToken(keyPair.privateKey, 'test-key', {
      iss: 'https://accounts.google.com',
      sub: 'google-sub',
      aud: CLIENT_ID,
      exp: now + 300,
      iat: now,
      email_verified: true,
      email: 'user@example.com',
      hd: 'example.com',
    })
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse(idToken))
      .mockResolvedValueOnce(Response.json({}, { status: 500 }))

    await expectGoogleError(
      authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
      'jwks_fetch_failed',
    )
  })

  it('classifies an invalid ID Token format', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse('not-a-jwt'))

    await expectGoogleError(
      authenticateGoogleUser('google-oauth-code', createOptions(fetchMock)),
      'invalid_id_token',
    )
  })

  it('does not expose credentials in a returned error', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(Response.json({}, { status: 400 }))
    const options = createOptions(fetchMock)

    const error = await authenticateGoogleUser(
      'google-oauth-code',
      options,
    ).catch((cause: unknown) => cause)
    const serializedError = JSON.stringify(error)

    expect(String(error)).not.toContain(options.clientSecret)
    expect(String(error)).not.toContain('google-oauth-code')
    expect(serializedError).not.toContain(options.clientSecret)
    expect(serializedError).not.toContain('google-oauth-code')
  })
})
