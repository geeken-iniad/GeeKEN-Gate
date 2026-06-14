import { describe, expect, it, vi } from 'vitest'

import {
  authenticateGitHubUser,
  type GitHubAuthOptions,
} from '../src/lib/github'

const GITHUB_API_VERSION = '2026-03-10'
const ACCESS_TOKEN = 'github-access-token'

function createOptions(fetchMock: ReturnType<typeof vi.fn>): GitHubAuthOptions {
  return {
    clientId: 'github-client-id',
    clientSecret: 'github-client-secret',
    callbackUrl: new URL('https://auth.example.com/callback'),
    organization: 'example-org',
    fetch: fetchMock as typeof globalThis.fetch,
  }
}

function createTokenResponse(): Response {
  return Response.json({
    access_token: ACCESS_TOKEN,
    token_type: 'bearer',
    scope: 'read:org',
  })
}

function createUserResponse(): Response {
  return Response.json({
    id: 123456,
    login: 'octocat',
  })
}

function expectGitHubError(
  promise: Promise<unknown>,
  code:
    | 'token_exchange_failed'
    | 'user_fetch_failed'
    | 'membership_fetch_failed'
    | 'membership_not_active'
    | 'invalid_response',
) {
  return expect(promise).rejects.toMatchObject({
    name: 'GitHubAuthError',
    message: code,
    code,
  })
}

describe('authenticateGitHubUser', () => {
  it('returns the authenticated user for an active organization membership', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        Response.json({
          access_token: ACCESS_TOKEN,
          token_type: 'bearer',
          scope: 'read:org',
        }),
      )
      .mockResolvedValueOnce(
        Response.json({
          id: 123456,
          login: 'octocat',
        }),
      )
      .mockResolvedValueOnce(
        Response.json({
          state: 'active',
        }),
      )

    await expect(
      authenticateGitHubUser('github-oauth-code', createOptions(fetchMock)),
    ).resolves.toEqual({
      githubId: '123456',
      githubLogin: 'octocat',
    })

    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      'https://github.com/login/oauth/access_token',
      {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          client_id: 'github-client-id',
          client_secret: 'github-client-secret',
          code: 'github-oauth-code',
          redirect_uri: 'https://auth.example.com/callback',
        }).toString(),
      },
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      'https://api.github.com/user',
      {
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${ACCESS_TOKEN}`,
          'User-Agent': 'GeeKEN-Gate',
          'X-GitHub-Api-Version': GITHUB_API_VERSION,
        },
      },
    )
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      'https://api.github.com/user/memberships/orgs/example-org',
      {
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${ACCESS_TOKEN}`,
          'User-Agent': 'GeeKEN-Gate',
          'X-GitHub-Api-Version': GITHUB_API_VERSION,
        },
      },
    )
  })

  it('rejects a pending organization membership', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse())
      .mockResolvedValueOnce(createUserResponse())
      .mockResolvedValueOnce(Response.json({ state: 'pending' }))

    await expectGitHubError(
      authenticateGitHubUser('github-oauth-code', createOptions(fetchMock)),
      'membership_not_active',
    )
  })

  it('rejects a user who is not an organization member', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse())
      .mockResolvedValueOnce(createUserResponse())
      .mockResolvedValueOnce(Response.json({}, { status: 404 }))

    await expectGitHubError(
      authenticateGitHubUser('github-oauth-code', createOptions(fetchMock)),
      'membership_not_active',
    )
  })

  it('rejects a membership request without sufficient scope', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse())
      .mockResolvedValueOnce(createUserResponse())
      .mockResolvedValueOnce(Response.json({}, { status: 403 }))

    await expectGitHubError(
      authenticateGitHubUser('github-oauth-code', createOptions(fetchMock)),
      'membership_fetch_failed',
    )
  })

  it('classifies an unsuccessful token exchange', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(Response.json({}, { status: 400 }))

    await expectGitHubError(
      authenticateGitHubUser('github-oauth-code', createOptions(fetchMock)),
      'token_exchange_failed',
    )
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('classifies an OAuth error returned with a successful HTTP status', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      Response.json({
        error: 'bad_verification_code',
        error_description: 'The code passed is incorrect or expired.',
      }),
    )

    await expectGitHubError(
      authenticateGitHubUser('github-oauth-code', createOptions(fetchMock)),
      'token_exchange_failed',
    )
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('rejects an access token without organization read scope', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      Response.json({
        access_token: ACCESS_TOKEN,
        token_type: 'bearer',
        scope: 'user:email',
      }),
    )

    await expectGitHubError(
      authenticateGitHubUser('github-oauth-code', createOptions(fetchMock)),
      'membership_fetch_failed',
    )
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('classifies an unsuccessful user request', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse())
      .mockResolvedValueOnce(Response.json({}, { status: 401 }))

    await expectGitHubError(
      authenticateGitHubUser('github-oauth-code', createOptions(fetchMock)),
      'user_fetch_failed',
    )
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('classifies an unsuccessful membership request', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(createTokenResponse())
      .mockResolvedValueOnce(createUserResponse())
      .mockResolvedValueOnce(Response.json({}, { status: 500 }))

    await expectGitHubError(
      authenticateGitHubUser('github-oauth-code', createOptions(fetchMock)),
      'membership_fetch_failed',
    )
  })

  it.each([
    [
      'token exchange',
      () => vi.fn().mockRejectedValueOnce(new Error('network unavailable')),
      'token_exchange_failed',
    ],
    [
      'user request',
      () =>
        vi
          .fn()
          .mockResolvedValueOnce(createTokenResponse())
          .mockRejectedValueOnce(new Error('network unavailable')),
      'user_fetch_failed',
    ],
    [
      'membership request',
      () =>
        vi
          .fn()
          .mockResolvedValueOnce(createTokenResponse())
          .mockResolvedValueOnce(createUserResponse())
          .mockRejectedValueOnce(new Error('network unavailable')),
      'membership_fetch_failed',
    ],
  ] as const)(
    'classifies a network failure during the %s',
    async (_caseName, createFetchMock, errorCode) => {
      const fetchMock = createFetchMock()

      await expectGitHubError(
        authenticateGitHubUser('github-oauth-code', createOptions(fetchMock)),
        errorCode,
      )
    },
  )

  it.each([
    [
      'token response',
      () =>
        vi
          .fn()
          .mockResolvedValueOnce(
            new Response('{', {
              headers: { 'Content-Type': 'application/json' },
            }),
          ),
    ],
    [
      'user response',
      () =>
        vi
          .fn()
          .mockResolvedValueOnce(createTokenResponse())
          .mockResolvedValueOnce(
            new Response('{', {
              headers: { 'Content-Type': 'application/json' },
            }),
          ),
    ],
    [
      'membership response',
      () =>
        vi
          .fn()
          .mockResolvedValueOnce(createTokenResponse())
          .mockResolvedValueOnce(createUserResponse())
          .mockResolvedValueOnce(
            new Response('{', {
              headers: { 'Content-Type': 'application/json' },
            }),
          ),
    ],
  ] as const)(
    'rejects invalid JSON in the %s',
    async (_caseName, createFetchMock) => {
      const fetchMock = createFetchMock()

      await expectGitHubError(
        authenticateGitHubUser('github-oauth-code', createOptions(fetchMock)),
        'invalid_response',
      )
    },
  )

  it.each([
    [
      'token response',
      () =>
        vi.fn().mockResolvedValueOnce(
          Response.json({
            access_token: '',
            token_type: 'bearer',
            scope: 'read:org',
          }),
        ),
    ],
    [
      'user response',
      () =>
        vi
          .fn()
          .mockResolvedValueOnce(createTokenResponse())
          .mockResolvedValueOnce(
            Response.json({
              id: '123456',
              login: 'octocat',
            }),
          ),
    ],
    [
      'membership response',
      () =>
        vi
          .fn()
          .mockResolvedValueOnce(createTokenResponse())
          .mockResolvedValueOnce(createUserResponse())
          .mockResolvedValueOnce(Response.json({ state: 'unknown' })),
    ],
  ] as const)(
    'rejects an invalid %s shape',
    async (_caseName, createFetchMock) => {
      const fetchMock = createFetchMock()

      await expectGitHubError(
        authenticateGitHubUser('github-oauth-code', createOptions(fetchMock)),
        'invalid_response',
      )
    },
  )

  it('does not expose credentials in a returned error', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(Response.json({}, { status: 400 }))
    const options = createOptions(fetchMock)

    const error = await authenticateGitHubUser(
      'github-oauth-code',
      options,
    ).catch((cause: unknown) => cause)
    const serializedError = JSON.stringify(error)

    expect(String(error)).not.toContain(options.clientSecret)
    expect(String(error)).not.toContain('github-oauth-code')
    expect(serializedError).not.toContain(options.clientSecret)
    expect(serializedError).not.toContain('github-oauth-code')
    expect(serializedError).not.toContain(ACCESS_TOKEN)
  })
})
