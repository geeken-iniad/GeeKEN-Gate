import type { Context, Handler } from 'hono'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import { generateRandomToken, hashAuthToken, verifyHashedToken } from '../lib/crypto'
import {
  authenticateGitHubUser,
  GitHubAuthError,
  type GitHubAuthenticatedUser,
} from '../lib/github'

const AUTH_CODE_LIFETIME_SECONDS = 2 * 60

type AppContext = Context<{ Bindings: AppBindings }>
type AuthenticateGitHubUser = typeof authenticateGitHubUser

interface OAuthStateRow {
  client_state: string
  client_id: string
  redirect_uri: string
  nonce: string
  code_challenge: string
  upstream_state_hash: string
}

interface AuditEvent {
  success: boolean
  provider: string
  userId?: string
  reason?: string
  clientId?: string
  redirectUri?: string
  user?: GitHubAuthenticatedUser
}

function getRequestMetadata(c: AppContext) {
  return {
    ipAddress: c.req.header('CF-Connecting-IP') ?? null,
    userAgent: c.req.header('User-Agent') ?? null,
  }
}

function prepareAuditEvent(
  c: AppContext,
  database: D1Database,
  event: AuditEvent,
  occurredAt: number,
): D1PreparedStatement {
  const { ipAddress, userAgent } = getRequestMetadata(c)

  return database
    .prepare(
      `INSERT INTO auth_events
         (event_type, provider, user_id, github_id, github_login, google_issuer,
          google_sub, client_id, redirect_uri, success, reason, ip_address,
          user_agent, occurred_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'callback',
      event.provider,
      event.userId ?? null,
      event.user?.githubId ?? null,
      event.user?.githubLogin ?? null,
      null,
      null,
      event.clientId ?? null,
      event.redirectUri ?? null,
      event.success ? 1 : 0,
      event.reason ?? null,
      ipAddress,
      userAgent,
      occurredAt,
    )
}

async function recordAuditEvent(
  c: AppContext,
  database: D1Database,
  event: AuditEvent,
  occurredAt: number,
): Promise<void> {
  await prepareAuditEvent(c, database, event, occurredAt).run()
}

function redirectWithError(
  redirectUri: string,
  clientState: string | null,
  error = 'access_denied',
): Response {
  const location = new URL(redirectUri)
  location.searchParams.set('error', error)

  if (clientState !== null) {
    location.searchParams.set('state', clientState)
  }

  return new Response(null, {
    status: 302,
    headers: {
      'Cache-Control': 'no-store',
      Location: location.href,
    },
  })
}

export function createCallbackHandler(
  authenticate: AuthenticateGitHubUser = authenticateGitHubUser,
): Handler<{ Bindings: AppBindings }> {
  return async (c) => {
    const code = c.req.query('code')
    const state = c.req.query('state')
    const config = await loadAuthServerConfig(c.env)
    const occurredAt = Math.floor(Date.now() / 1000)

    if (!code || !state) {
      await recordAuditEvent(
        c,
        config.db,
        { success: false, provider: 'github', reason: 'invalid_request' },
        occurredAt,
      )

      c.header('Cache-Control', 'no-store')
      return c.json({ error: 'invalid_request' }, 400)
    }

    const stateHash = await hashAuthToken(
      state,
      config.tokenHashSecret,
      'oauth-upstream-state',
    )
    const oauthState = await config.db
      .prepare(
        `DELETE FROM oauth_states
         WHERE upstream_state_hash = ?
           AND provider = 'github'
           AND expires_at > ?
         RETURNING client_state, client_id, redirect_uri, nonce, code_challenge,
                  upstream_state_hash`,
      )
      .bind(stateHash, occurredAt)
      .first<OAuthStateRow>()

    if (
      oauthState === null ||
      !(await verifyHashedToken(
        state,
        oauthState.upstream_state_hash,
        config.tokenHashSecret,
        'oauth-upstream-state',
      ))
    ) {
      await recordAuditEvent(
        c,
        config.db,
        { success: false, provider: 'github', reason: 'invalid_state' },
        occurredAt,
      )

      c.header('Cache-Control', 'no-store')
      return c.json({ error: 'invalid_request' }, 400)
    }

    let user: GitHubAuthenticatedUser

    try {
      user = await authenticate(code, {
        clientId: config.githubClientId,
        clientSecret: config.githubClientSecret,
        callbackUrl: config.githubCallbackUrl,
        organization: config.githubOrg,
      })
    } catch (error) {
      const reason =
        error instanceof GitHubAuthError ? error.code : 'github_auth_failed'

      await recordAuditEvent(
        c,
        config.db,
        {
          success: false,
          provider: 'github',
          reason,
          clientId: oauthState.client_id,
          redirectUri: oauthState.redirect_uri,
        },
        occurredAt,
      )

      return redirectWithError(
        oauthState.redirect_uri,
        oauthState.client_state,
      )
    }

    const identity = await config.db
      .prepare(
        `SELECT user_id, frozen_at
         FROM github_identities
         WHERE github_id = ?
         LIMIT 1`,
      )
      .bind(user.githubId)
      .first<{ user_id: string; frozen_at: number | null }>()

    let userId: string

    if (identity === null) {
      userId = crypto.randomUUID()
      await config.db.batch([
        config.db
          .prepare(
            `INSERT INTO users
               (id, created_at, updated_at)
             VALUES (?, ?, ?)`,
          )
          .bind(userId, occurredAt, occurredAt),
        config.db
          .prepare(
            `INSERT INTO github_identities
               (github_id, user_id, github_login, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?)`,
          )
          .bind(user.githubId, userId, user.githubLogin, occurredAt, occurredAt),
      ])
    } else {
      if (identity.frozen_at !== null) {
        await recordAuditEvent(
          c,
          config.db,
          {
            success: false,
            provider: 'github',
            reason: 'frozen_identity',
            userId: identity.user_id,
            clientId: oauthState.client_id,
            redirectUri: oauthState.redirect_uri,
            user,
          },
          occurredAt,
        )

        return redirectWithError(
          oauthState.redirect_uri,
          oauthState.client_state,
        )
      }

      userId = identity.user_id
      await config.db
        .prepare(
          `UPDATE github_identities
           SET github_login = ?, updated_at = ?
           WHERE github_id = ?`,
        )
        .bind(user.githubLogin, occurredAt, user.githubId)
        .run()
    }

    const authCode = generateRandomToken()
    const authCodeHash = await hashAuthToken(
      authCode,
      config.tokenHashSecret,
      'auth-code',
    )

    await config.db.batch([
      config.db
        .prepare(
          `INSERT INTO auth_codes
             (code_hash, user_id, client_id, redirect_uri, nonce,
              code_challenge, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          authCodeHash,
          userId,
          oauthState.client_id,
          oauthState.redirect_uri,
          oauthState.nonce,
          oauthState.code_challenge,
          occurredAt,
          occurredAt + AUTH_CODE_LIFETIME_SECONDS,
        ),
      prepareAuditEvent(
        c,
        config.db,
        {
          success: true,
          provider: 'github',
          userId,
          clientId: oauthState.client_id,
          redirectUri: oauthState.redirect_uri,
          user,
        },
        occurredAt,
      ),
    ])

    const redirectUrl = new URL(oauthState.redirect_uri)
    redirectUrl.searchParams.set('code', authCode)
    redirectUrl.searchParams.set('state', oauthState.client_state)

    return new Response(null, {
      status: 302,
      headers: {
        'Cache-Control': 'no-store',
        Location: redirectUrl.href,
      },
    })
  }
}

export const handleCallbackGitHub = createCallbackHandler()
