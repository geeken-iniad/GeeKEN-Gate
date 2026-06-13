export interface GitHubAuthOptions {
  clientId: string
  clientSecret: string
  callbackUrl: URL
  organization: string
  fetch?: typeof globalThis.fetch
}

export interface GitHubAuthenticatedUser {
  githubId: string
  githubLogin: string
}

export type GitHubAuthErrorCode =
  | 'token_exchange_failed'
  | 'user_fetch_failed'
  | 'membership_fetch_failed'
  | 'membership_not_active'
  | 'invalid_response'

export class GitHubAuthError extends Error {
  constructor(
    public readonly code: GitHubAuthErrorCode,
    options?: ErrorOptions,
  ) {
    super(code, options)
    this.name = 'GitHubAuthError'
  }
}

const GITHUB_ACCESS_TOKEN_URL =
  'https://github.com/login/oauth/access_token'
const GITHUB_API_URL = 'https://api.github.com'
const GITHUB_API_VERSION = '2026-03-10'

type GitHubEndpointErrorCode =
  | 'token_exchange_failed'
  | 'user_fetch_failed'
  | 'membership_fetch_failed'

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

async function requestGitHub(
  fetchFunction: typeof globalThis.fetch,
  input: string,
  init: RequestInit,
  errorCode: GitHubEndpointErrorCode,
): Promise<Response> {
  let response: Response

  try {
    response = await fetchFunction(input, init)
  } catch (cause) {
    throw new GitHubAuthError(errorCode, { cause })
  }

  if (!response.ok) {
    throw new GitHubAuthError(errorCode)
  }

  return response
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json()
  } catch (cause) {
    throw new GitHubAuthError('invalid_response', { cause })
  }
}

function createApiHeaders(accessToken: string): Record<string, string> {
  return {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${accessToken}`,
    'X-GitHub-Api-Version': GITHUB_API_VERSION,
  }
}

export async function authenticateGitHubUser(
  code: string,
  options: GitHubAuthOptions,
): Promise<GitHubAuthenticatedUser> {
  const fetchFunction = options.fetch ?? globalThis.fetch
  const tokenResponse = await requestGitHub(
    fetchFunction,
    GITHUB_ACCESS_TOKEN_URL,
    {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: options.clientId,
        client_secret: options.clientSecret,
        code,
        redirect_uri: options.callbackUrl.href,
      }).toString(),
    },
    'token_exchange_failed',
  )
  const tokenPayload = await readJson(tokenResponse)

  if (
    isRecord(tokenPayload) &&
    typeof tokenPayload.error === 'string'
  ) {
    throw new GitHubAuthError('token_exchange_failed')
  }

  if (
    !isRecord(tokenPayload) ||
    typeof tokenPayload.access_token !== 'string' ||
    tokenPayload.access_token.length === 0 ||
    tokenPayload.token_type !== 'bearer' ||
    typeof tokenPayload.scope !== 'string'
  ) {
    throw new GitHubAuthError('invalid_response')
  }

  const grantedScopes = tokenPayload.scope
    .split(',')
    .map((scope) => scope.trim())

  if (
    !grantedScopes.includes('read:org') &&
    !grantedScopes.includes('admin:org')
  ) {
    throw new GitHubAuthError('membership_fetch_failed')
  }

  const apiHeaders = createApiHeaders(tokenPayload.access_token)
  const userResponse = await requestGitHub(
    fetchFunction,
    `${GITHUB_API_URL}/user`,
    { headers: apiHeaders },
    'user_fetch_failed',
  )
  const userPayload = await readJson(userResponse)

  if (
    !isRecord(userPayload) ||
    typeof userPayload.id !== 'number' ||
    !Number.isSafeInteger(userPayload.id) ||
    userPayload.id <= 0 ||
    typeof userPayload.login !== 'string' ||
    userPayload.login.length === 0
  ) {
    throw new GitHubAuthError('invalid_response')
  }

  let membershipResponse: Response

  try {
    membershipResponse = await fetchFunction(
      `${GITHUB_API_URL}/user/memberships/orgs/${encodeURIComponent(options.organization)}`,
      { headers: apiHeaders },
    )
  } catch (cause) {
    throw new GitHubAuthError('membership_fetch_failed', { cause })
  }

  if (membershipResponse.status === 404) {
    throw new GitHubAuthError('membership_not_active')
  }

  if (!membershipResponse.ok) {
    throw new GitHubAuthError('membership_fetch_failed')
  }

  const membershipPayload = await readJson(membershipResponse)

  if (
    !isRecord(membershipPayload) ||
    (membershipPayload.state !== 'active' &&
      membershipPayload.state !== 'pending')
  ) {
    throw new GitHubAuthError('invalid_response')
  }

  if (membershipPayload.state !== 'active') {
    throw new GitHubAuthError('membership_not_active')
  }

  return {
    githubId: String(userPayload.id),
    githubLogin: userPayload.login,
  }
}
