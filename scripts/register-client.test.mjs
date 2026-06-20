import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  buildRegistrationSql,
  parseArguments,
  registerClient,
  validateClientId,
  validateRedirectUri,
} from './register-client.mjs'

describe('register-client operations', () => {
  it('registers a public client without generating a secret', () => {
    const calls = []
    const result = registerClient(
      ['--local', 'client-a', 'https://client.example/callback'],
      {
        now: () => 1_800_000_000,
        runWrangler: (arguments_) => {
          calls.push(arguments_)
        },
      },
    )

    assert.deepEqual(result, {
      clientId: 'client-a',
      redirectUri: 'https://client.example/callback',
    })
    assert.equal(calls.length, 1)
    assert.deepEqual(calls[0].slice(0, 6), [
      'd1',
      'execute',
      'DB',
      '--local',
      '--yes',
      '--command',
    ])
    assert.match(calls[0][6], /INSERT INTO clients/)
    assert.match(calls[0][6], /INSERT INTO allowed_redirect_uris/)
    assert.doesNotMatch(calls[0][6], /client_secret/)
  })

  it('does not return a secret when D1 registration fails', () => {
    assert.throws(
      () =>
        registerClient(
          ['--remote', 'client-a', 'https://client.example/callback'],
          {
            runWrangler: () => {
              throw new Error('D1 registration failed')
            },
          },
        ),
      /D1 registration failed/,
    )
  })

  it('does not call D1 when validation fails', () => {
    let called = false

    assert.throws(() =>
      registerClient(
        ['--local', 'client-a', 'http://client.example/callback'],
        {
          runWrangler: () => {
            called = true
          },
        },
      ),
    )
    assert.equal(called, false)
  })

  it('escapes SQL string values', () => {
    const sql = buildRegistrationSql({
      clientId: "client'a",
      redirectUri: "https://client.example/callback?value='",
      createdAt: 1_800_000_000,
    })

    assert.match(sql, /client''a/)
    assert.match(sql, /value=''/)
    assert.doesNotMatch(sql, /client_secret/)
  })

  it('requires exactly one target and two positional arguments', () => {
    assert.deepEqual(
      parseArguments([
        '--',
        '--remote',
        'client-a',
        'https://client.example/callback',
      ]),
      {
        target: '--remote',
        clientId: 'client-a',
        redirectUri: 'https://client.example/callback',
      },
    )
    assert.throws(
      () =>
        parseArguments([
          '--local',
          '--remote',
          'client-a',
          'https://client.example/callback',
        ]),
      /Usage:/,
    )
  })

  it('validates client IDs', () => {
    assert.equal(validateClientId('client-a_1.example'), 'client-a_1.example')
    assert.throws(() => validateClientId('client id'), /Client ID/)
    assert.throws(() => validateClientId(''), /Client ID/)
  })

  it('allows HTTPS and loopback HTTP redirect URIs', () => {
    assert.equal(
      validateRedirectUri('https://client.example/callback'),
      'https://client.example/callback',
    )
    assert.equal(
      validateRedirectUri('http://localhost:3000/callback'),
      'http://localhost:3000/callback',
    )
    assert.equal(
      validateRedirectUri('http://127.0.0.1:3000/callback'),
      'http://127.0.0.1:3000/callback',
    )
  })

  it('rejects insecure or ambiguous redirect URIs', () => {
    for (const redirectUri of [
      'http://client.example/callback',
      'ftp://client.example/callback',
      'https://user:password@client.example/callback',
      'https://client.example/callback#fragment',
      'not-a-url',
    ]) {
      assert.throws(() => validateRedirectUri(redirectUri))
    }
  })
})
