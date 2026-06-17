import { describe, expect, it } from 'vitest'

import { app } from '../src/index'
import { createBindings } from './oidc-helpers'

describe('OIDC discovery and JWKS', () => {
  it('returns minimal OIDC discovery metadata', async () => {
    const response = await app.request(
      'https://auth.example.com/.well-known/openid-configuration',
      {},
      createBindings(),
    )

    expect(response.status).toBe(200)
    const metadata = (await response.json()) as Record<string, unknown>

    expect(metadata).toEqual({
      issuer: 'https://auth.example.com',
      authorization_endpoint: 'https://auth.example.com/authorize',
      token_endpoint: 'https://auth.example.com/token',
      userinfo_endpoint: 'https://auth.example.com/userinfo',
      jwks_uri: 'https://auth.example.com/jwks.json',
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid'],
      token_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'],
    })
  })

  it('returns only public key material in JWKS', async () => {
    const response = await app.request(
      'https://auth.example.com/jwks.json',
      {},
      createBindings(),
    )

    expect(response.status).toBe(200)
    const body = (await response.json()) as { keys: JsonWebKey[] }

    expect(body.keys).toHaveLength(1)
    const jwk = body.keys[0] as Record<string, unknown>
    expect(jwk.kty).toBe('RSA')
    expect(jwk.alg).toBe('RS256')
    expect(jwk.use).toBe('sig')
    expect(jwk.kid).toBe('test-key')
    expect(typeof jwk.n).toBe('string')
    expect(typeof jwk.e).toBe('string')
    expect(jwk.d).toBeUndefined()
    expect(jwk.p).toBeUndefined()
    expect(jwk.q).toBeUndefined()
    expect(jwk.dp).toBeUndefined()
    expect(jwk.dq).toBeUndefined()
    expect(jwk.qi).toBeUndefined()
  })
})
