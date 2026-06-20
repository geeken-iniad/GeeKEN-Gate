import { describe, expect, it } from 'vitest'

import {
  generateCodeChallenge,
  generateCodeVerifier,
  generateRandomToken,
  hashAuthToken,
  hashEmailAddress,
  normalizeEmail,
  verifyHashedToken,
} from '../src/lib/crypto'

const LOWERCASE_SHA256_HEX = /^[0-9a-f]{64}$/
const BASE64URL_32_BYTES = /^[A-Za-z0-9_-]{43}$/

describe('random credential generation', () => {
  it('generates URL-safe tokens with 32 bytes of entropy', () => {
    expect(generateRandomToken()).toMatch(BASE64URL_32_BYTES)
    expect(generateCodeVerifier()).toMatch(BASE64URL_32_BYTES)
  })

  it('generates a different value on each call', () => {
    const tokens = new Set(
      Array.from({ length: 32 }, () => generateRandomToken()),
    )

    expect(tokens.size).toBe(32)
  })
})

describe('PKCE generation', () => {
  it('generates an S256 code challenge from a verifier', async () => {
    const verifier = generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)

    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/)

    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(verifier),
    )
    const expected = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replace(/=+$/, '')

    expect(challenge).toBe(expected)
  })
})

describe('authentication token hashing', () => {
  it('returns a deterministic lowercase SHA-256 HMAC', async () => {
    const firstHash = await hashAuthToken(
      'token-value',
      'hash-secret',
      'auth-code',
    )
    const secondHash = await hashAuthToken(
      'token-value',
      'hash-secret',
      'auth-code',
    )

    expect(firstHash).toMatch(LOWERCASE_SHA256_HEX)
    expect(secondHash).toBe(firstHash)
  })

  it('separates hashes by purpose', async () => {
    const hashes = await Promise.all([
      hashAuthToken('token-value', 'hash-secret', 'oauth-upstream-state'),
      hashAuthToken('token-value', 'hash-secret', 'auth-code'),
      hashAuthToken('token-value', 'hash-secret', 'access-token'),
      hashAuthToken('token-value', 'hash-secret', 'refresh-token'),
      hashAuthToken('other-value', 'hash-secret', 'auth-code'),
    ])

    expect(new Set(hashes).size).toBe(5)
  })

  it('changes when the value or secret changes', async () => {
    const original = await hashAuthToken(
      'token-value',
      'hash-secret',
      'auth-code',
    )
    const changedValue = await hashAuthToken(
      'other-token',
      'hash-secret',
      'auth-code',
    )
    const changedSecret = await hashAuthToken(
      'token-value',
      'other-secret',
      'auth-code',
    )

    expect(changedValue).not.toBe(original)
    expect(changedSecret).not.toBe(original)
  })

  it('rejects an empty HMAC secret', async () => {
    await expect(
      hashAuthToken('token-value', '', 'auth-code'),
    ).rejects.toThrow('HMAC secret must not be empty')
  })
})

describe('hash verification', () => {
  it('accepts only the matching token', async () => {
    const hash = await hashAuthToken('token-value', 'hash-secret', 'auth-code')

    await expect(
      verifyHashedToken('token-value', hash, 'hash-secret', 'auth-code'),
    ).resolves.toBe(true)
    await expect(
      verifyHashedToken('wrong-value', hash, 'hash-secret', 'auth-code'),
    ).resolves.toBe(false)
  })

  it('returns false for malformed stored hashes', async () => {
    await expect(
      verifyHashedToken(
        'token-value',
        'a'.repeat(63),
        'hash-secret',
        'auth-code',
      ),
    ).resolves.toBe(false)
    await expect(
      verifyHashedToken(
        'token-value',
        'A'.repeat(64),
        'hash-secret',
        'auth-code',
      ),
    ).resolves.toBe(false)
    await expect(
      verifyHashedToken(
        'token-value',
        `${'a'.repeat(63)}g`,
        'hash-secret',
        'auth-code',
      ),
    ).resolves.toBe(false)
  })
})

describe('email normalization and hashing', () => {
  it('normalizes email with trim and lower case', () => {
    expect(normalizeEmail('  User@Example.COM  ')).toBe('user@example.com')
  })

  it('returns a deterministic lowercase SHA-256 HMAC for email', async () => {
    const firstHash = await hashEmailAddress(
      'user@example.com',
      'pepper-secret',
    )
    const secondHash = await hashEmailAddress(
      'user@example.com',
      'pepper-secret',
    )

    expect(firstHash).toMatch(LOWERCASE_SHA256_HEX)
    expect(secondHash).toBe(firstHash)
  })

  it('produces different email hashes for different peppers or addresses', async () => {
    const [samePepperDifferentEmail, differentPepperSameEmail] =
      await Promise.all([
        hashEmailAddress('other@example.com', 'pepper-secret'),
        hashEmailAddress('user@example.com', 'other-pepper'),
      ])
    const original = await hashEmailAddress('user@example.com', 'pepper-secret')

    expect(samePepperDifferentEmail).not.toBe(original)
    expect(differentPepperSameEmail).not.toBe(original)
  })

  it('rejects an empty email HMAC pepper', async () => {
    await expect(
      hashEmailAddress('user@example.com', ''),
    ).rejects.toThrow('Email HMAC pepper must not be empty')
  })
})
