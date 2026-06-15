import { describe, expect, it, vi } from 'vitest'

import { bytesToBase64Url } from '../src/lib/crypto'
import { verifyGoogleIdToken } from '../src/lib/google'

const NOW = 1_700_000_000

async function createSignedToken(overrides: Record<string, unknown> = {}) {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey) as JsonWebKey
  Object.assign(publicJwk, { kid: 'kid-1', alg: 'RS256', use: 'sig' })
  const header = bytesToBase64Url(new TextEncoder().encode(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'kid-1' })))
  const claims = bytesToBase64Url(new TextEncoder().encode(JSON.stringify({
    iss: 'https://accounts.google.com',
    aud: 'google-client-id',
    exp: NOW + 300,
    iat: NOW,
    nonce: 'nonce-value',
    sub: 'google-sub',
    email: ' Member@Example.COM ',
    email_verified: true,
    hd: 'example.com',
    ...overrides,
  })))
  const signingInput = `${header}.${claims}`
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', keyPair.privateKey, new TextEncoder().encode(signingInput))
  return {
    token: `${signingInput}.${bytesToBase64Url(new Uint8Array(signature))}`,
    jwks: { keys: [publicJwk] },
  }
}

function options(fetchMock: ReturnType<typeof vi.fn>) {
  return {
    clientId: 'google-client-id',
    allowedHostedDomains: ['example.com'],
    nonce: 'nonce-value',
    fetch: fetchMock as typeof globalThis.fetch,
    now: NOW,
  }
}

describe('verifyGoogleIdToken', () => {
  it('validates signature and required Google claims', async () => {
    const { token, jwks } = await createSignedToken()
    const fetchMock = vi.fn().mockResolvedValue(Response.json(jwks))

    await expect(verifyGoogleIdToken(token, options(fetchMock))).resolves.toEqual({
      googleSub: 'google-sub',
      email: 'member@example.com',
      hostedDomain: 'example.com',
      name: undefined,
    })
  })

  it.each([
    ['issuer', { iss: 'https://evil.example' }, 'google_id_token_invalid'],
    ['audience', { aud: 'other-client' }, 'google_id_token_invalid'],
    ['expired token', { exp: NOW - 301 }, 'google_id_token_invalid'],
    ['recently expired token', { exp: NOW - 1 }, 'google_id_token_invalid'],
    ['future iat', { iat: NOW + 301 }, 'google_id_token_invalid'],
    ['old iat', { iat: NOW - 24 * 60 * 60 - 1 }, 'google_id_token_invalid'],
    ['nonce', { nonce: 'wrong' }, 'google_id_token_invalid'],
    ['missing sub', { sub: '' }, 'google_id_token_invalid'],
    ['missing email', { email: '  ' }, 'google_email_missing'],
    ['unverified email', { email_verified: false }, 'google_email_not_verified'],
    ['missing hd', { hd: '' }, 'google_hd_missing'],
    ['not allowed hd', { hd: 'other.example' }, 'google_hd_not_allowed'],
  ])('rejects invalid %s', async (_caseName, overrides, code) => {
    const { token, jwks } = await createSignedToken(overrides)
    const fetchMock = vi.fn().mockResolvedValue(Response.json(jwks))

    await expect(verifyGoogleIdToken(token, options(fetchMock))).rejects.toMatchObject({ code })
  })

  it('rejects an invalid signature', async () => {
    const { token, jwks } = await createSignedToken()
    const parts = token.split('.')
    parts[2] = `${parts[2].startsWith('A') ? 'B' : 'A'}${parts[2].slice(1)}`
    const tampered = parts.join('.')
    const fetchMock = vi.fn().mockResolvedValue(Response.json(jwks))

    await expect(verifyGoogleIdToken(tampered, options(fetchMock))).rejects.toMatchObject({
      code: 'google_id_token_invalid',
    })
  })
})
