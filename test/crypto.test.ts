import { describe, expect, it } from 'vitest'

import {
  generateClientSecret,
  generateRandomToken,
  hashAuthToken,
  hashClientSecret,
  verifyClientSecret,
} from '../src/lib/crypto'

const LOWERCASE_SHA256_HEX = /^[0-9a-f]{64}$/
const BASE64URL_32_BYTES = /^[A-Za-z0-9_-]{43}$/

describe('random credential generation', () => {
  it('generates URL-safe tokens with 32 bytes of entropy', () => {
    expect(generateRandomToken()).toMatch(BASE64URL_32_BYTES)
    expect(generateClientSecret()).toMatch(BASE64URL_32_BYTES)
  })

  it('generates a different value on each call', () => {
    const tokens = new Set(
      Array.from({ length: 32 }, () => generateRandomToken()),
    )

    expect(tokens.size).toBe(32)
  })
})

describe('authentication token hashing', () => {
  it('returns a deterministic lowercase SHA-256 HMAC', async () => {
    const firstHash = await hashAuthToken(
      'token-value',
      'session-secret',
      'session',
    )
    const secondHash = await hashAuthToken(
      'token-value',
      'session-secret',
      'session',
    )

    expect(firstHash).toMatch(LOWERCASE_SHA256_HEX)
    expect(secondHash).toBe(firstHash)
  })

  it('separates hashes by purpose', async () => {
    const hashes = await Promise.all([
      hashAuthToken('token-value', 'session-secret', 'session'),
      hashAuthToken('token-value', 'session-secret', 'oauth-state'),
      hashAuthToken('token-value', 'session-secret', 'auth-code'),
    ])

    expect(new Set(hashes).size).toBe(3)
  })

  it('changes when the value or secret changes', async () => {
    const original = await hashAuthToken(
      'token-value',
      'session-secret',
      'session',
    )
    const changedValue = await hashAuthToken(
      'other-token',
      'session-secret',
      'session',
    )
    const changedSecret = await hashAuthToken(
      'token-value',
      'other-secret',
      'session',
    )

    expect(changedValue).not.toBe(original)
    expect(changedSecret).not.toBe(original)
  })

  it('rejects an empty HMAC secret', async () => {
    await expect(
      hashAuthToken('token-value', '', 'session'),
    ).rejects.toThrow('HMAC secret must not be empty')
  })
})

describe('client secret hashing and verification', () => {
  it('hashes a client secret as lowercase SHA-256 hex', async () => {
    const hash = await hashClientSecret('client-secret')

    expect(hash).toMatch(LOWERCASE_SHA256_HEX)
  })

  it('accepts only the matching client secret', async () => {
    const hash = await hashClientSecret('client-secret')

    await expect(verifyClientSecret('client-secret', hash)).resolves.toBe(true)
    await expect(verifyClientSecret('wrong-secret', hash)).resolves.toBe(false)
  })

  it('returns false for malformed stored hashes', async () => {
    await expect(
      verifyClientSecret('client-secret', 'a'.repeat(63)),
    ).resolves.toBe(false)
    await expect(
      verifyClientSecret('client-secret', 'A'.repeat(64)),
    ).resolves.toBe(false)
    await expect(
      verifyClientSecret('client-secret', `${'a'.repeat(63)}g`),
    ).resolves.toBe(false)
  })
})
