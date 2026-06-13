import type { Context, Handler } from 'hono'
import { setCookie } from 'hono/cookie'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import { generateRandomToken, hashAuthToken } from '../lib/crypto'
import {
  authenticateGitHubUser,
  GitHubAuthError,
  type GitHubAuthenticatedUser,
} from '../lib/github'

const SESSION_COOKIE_NAME = 'giken_session'
const SESSION_LIFETIME_SECONDS = 7 * 24 * 60 * 60
const AUTH_CODE_LIFETIME_SECONDS = 2 * 60

type AppContext = Context<{ Bindings: AppBindings }>
type AuthenticateGitHubUser = typeof authenticateGitHubUser

interface OAuthStateRow {
  client_id: string
  redirect_uri: string
}

interface AuditEvent {
  success: boolean
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
         (event_type, github_id, github_login, client_id, redirect_uri,
          success, reason, ip_address, user_agent, occurred_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'callback',
      event.user?.githubId ?? null,
      event.user?.githubLogin ?? null,
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

function redirectWithError(redirectUri: string): Response {
  const location = new URL(redirectUri)
  location.searchParams.set('error', 'access_denied')

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
    const config = loadAuthServerConfig(c.env)
    const occurredAt = Math.floor(Date.now() / 1000)

    if (!code || !state) {
      await recordAuditEvent(
        c,
        config.db,
        { success: false, reason: 'invalid_request' },
        occurredAt,
      )

      c.header('Cache-Control', 'no-store')
      return c.json({ error: 'invalid_request' }, 400)
    }

    const stateHash = await hashAuthToken(
      state,
      config.sessionSecret,
      'oauth-state',
    )
    const oauthState = await config.db
      .prepare(
        `DELETE FROM oauth_states
         WHERE state_hash = ?
           AND expires_at > ?
         RETURNING client_id, redirect_uri`,
      )
      .bind(stateHash, occurredAt)
      .first<OAuthStateRow>()

    if (oauthState === null) {
      await recordAuditEvent(
        c,
        config.db,
        { success: false, reason: 'invalid_state' },
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
          reason,
          clientId: oauthState.client_id,
          redirectUri: oauthState.redirect_uri,
        },
        occurredAt,
      )

      return redirectWithError(oauthState.redirect_uri)
    }

    const frozenUser = await config.db
      .prepare(
        `SELECT 1
         FROM frozen_users
         WHERE github_id = ?
         LIMIT 1`,
      )
      .bind(user.githubId)
      .first()

    if (frozenUser !== null) {
      await recordAuditEvent(
        c,
        config.db,
        {
          success: false,
          reason: 'frozen_user',
          clientId: oauthState.client_id,
          redirectUri: oauthState.redirect_uri,
          user,
        },
        occurredAt,
      )

      return redirectWithError(oauthState.redirect_uri)
    }

    const session = generateRandomToken()
    const authCode = generateRandomToken()
    const [sessionHash, authCodeHash] = await Promise.all([
      hashAuthToken(session, config.sessionSecret, 'session'),
      hashAuthToken(authCode, config.sessionSecret, 'auth-code'),
    ])

    await config.db.batch([
      config.db
        .prepare(
          `INSERT INTO users
             (github_id, github_login, created_at, updated_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT (github_id) DO UPDATE SET
             github_login = excluded.github_login,
             updated_at = excluded.updated_at`,
        )
        .bind(user.githubId, user.githubLogin, occurredAt, occurredAt),
      config.db
        .prepare(
          `INSERT INTO sessions
             (session_hash, github_id, created_at, expires_at)
           VALUES (?, ?, ?, ?)`,
        )
        .bind(
          sessionHash,
          user.githubId,
          occurredAt,
          occurredAt + SESSION_LIFETIME_SECONDS,
        ),
      config.db
        .prepare(
          `INSERT INTO auth_codes
             (code_hash, github_id, client_id, redirect_uri,
              created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          authCodeHash,
          user.githubId,
          oauthState.client_id,
          oauthState.redirect_uri,
          occurredAt,
          occurredAt + AUTH_CODE_LIFETIME_SECONDS,
        ),
      prepareAuditEvent(
        c,
        config.db,
        {
          success: true,
          clientId: oauthState.client_id,
          redirectUri: oauthState.redirect_uri,
          user,
        },
        occurredAt,
      ),
    ])

    setCookie(c, SESSION_COOKIE_NAME, session, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      path: '/',
      maxAge: SESSION_LIFETIME_SECONDS,
    })
    c.header('Cache-Control', 'no-store')

    const redirectUrl = new URL(oauthState.redirect_uri)
    redirectUrl.searchParams.set('code', authCode)

    return c.redirect(redirectUrl.href)
  }
}

export const handleCallback = createCallbackHandler()
