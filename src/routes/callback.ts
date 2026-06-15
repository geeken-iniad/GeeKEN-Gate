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
import {
  getUserAdmission,
  GoogleAdmissionError,
  resolveGitHubIdentity,
  resolveGoogleIdentity,
} from '../lib/identity'
import {
  authenticateGoogleUser,
  GoogleAuthError,
  type GoogleAuthenticatedUser,
} from '../lib/google'

const SESSION_COOKIE_NAME = 'giken_session'
const SESSION_LIFETIME_SECONDS = 7 * 24 * 60 * 60
const AUTH_CODE_LIFETIME_SECONDS = 2 * 60

type AppContext = Context<{ Bindings: AppBindings }>
type AuthenticateGitHubUser = typeof authenticateGitHubUser
type AuthenticateGoogleUser = typeof authenticateGoogleUser

interface OAuthStateRow {
  client_id: string
  redirect_uri: string
  client_state: string | null
  scope: string | null
  nonce: string | null
  provider: string | null
  code_challenge: string | null
  code_challenge_method: string | null
}

function includesScope(scope: string | null, required: string): boolean {
  return scope?.split(/\s+/).includes(required) ?? false
}

function hasRequiredOidcState(oauthState: OAuthStateRow): boolean {
  return (oauthState.provider === 'github' || oauthState.provider === 'google') && includesScope(oauthState.scope, 'openid') && !!oauthState.nonce
}

interface AuditEvent {
  success: boolean
  reason?: string
  clientId?: string
  redirectUri?: string
  user?: GitHubAuthenticatedUser
  googleUser?: GoogleAuthenticatedUser
  provider?: 'github' | 'google'
  userId?: string
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
         (event_type, user_id, provider, github_id, github_login, client_id,
          redirect_uri, success, reason, ip_address, user_agent, occurred_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'callback',
      event.userId ?? null,
      event.provider ?? (event.user ? 'github' : event.googleUser ? 'google' : null),
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

function redirectWithError(redirectUri: string, state?: string | null): Response {
  const location = new URL(redirectUri)
  location.searchParams.set('error', 'access_denied')
  if (state) location.searchParams.set('state', state)

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
  authenticateGoogle: AuthenticateGoogleUser = authenticateGoogleUser,
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
         RETURNING client_id, redirect_uri, client_state, scope, nonce, provider,
                   code_challenge, code_challenge_method`,
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

    if (!hasRequiredOidcState(oauthState)) {
      await recordAuditEvent(
        c,
        config.db,
        { success: false, reason: 'invalid_oidc_state' },
        occurredAt,
      )

      c.header('Cache-Control', 'no-store')
      return c.json({ error: 'invalid_request' }, 400)
    }

    let identity: { userId: string }
    let user: GitHubAuthenticatedUser | undefined
    let googleUser: GoogleAuthenticatedUser | undefined

    if (oauthState.provider === 'google') {
      try {
        googleUser = await authenticateGoogle(code, {
          clientId: config.googleClientId,
          clientSecret: config.googleClientSecret,
          callbackUrl: config.googleCallbackUrl,
          allowedHostedDomains: config.googleAllowedHostedDomains,
          nonce: oauthState.nonce!,
        })
        identity = await resolveGoogleIdentity(config.db, googleUser, occurredAt)
      } catch (error) {
        const reason =
          error instanceof GoogleAuthError || error instanceof GoogleAdmissionError
            ? error.code
            : 'google_id_token_invalid'

        await recordAuditEvent(
          c,
          config.db,
          {
            success: false,
            provider: 'google',
            reason,
            clientId: oauthState.client_id,
            redirectUri: oauthState.redirect_uri,
          },
          occurredAt,
        )

        return redirectWithError(oauthState.redirect_uri, oauthState.client_state)
      }
    } else {
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

        return redirectWithError(oauthState.redirect_uri, oauthState.client_state)
      }
      identity = await resolveGitHubIdentity(config.db, user, occurredAt)
    }

    const admission = oauthState.provider === 'google'
      ? { allowed: true as const }
      : await getUserAdmission(config.db, identity.userId)

    if (!admission.allowed) {
      await recordAuditEvent(
        c,
        config.db,
        {
          success: false,
          provider: oauthState.provider as 'github' | 'google',
          reason: admission.reason,
          clientId: oauthState.client_id,
          redirectUri: oauthState.redirect_uri,
          user,
          googleUser,
          userId: identity.userId,
        },
        occurredAt,
      )

      return redirectWithError(oauthState.redirect_uri, oauthState.client_state)
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
          `INSERT INTO sessions
             (session_hash, user_id, created_at, expires_at)
           VALUES (?, ?, ?, ?)`,
        )
        .bind(
          sessionHash,
          identity.userId,
          occurredAt,
          occurredAt + SESSION_LIFETIME_SECONDS,
        ),
      config.db
        .prepare(
          `INSERT INTO auth_codes
               (code_hash, user_id, client_id, redirect_uri, scope, nonce, provider,
                provider_user_id, auth_time, code_challenge, code_challenge_method, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          authCodeHash,
          identity.userId,
          oauthState.client_id,
          oauthState.redirect_uri,
          oauthState.scope,
          oauthState.nonce,
          oauthState.provider,
          oauthState.provider === 'google' ? googleUser!.googleSub : user!.githubId,
          occurredAt,
          oauthState.code_challenge,
          oauthState.code_challenge_method,
          occurredAt,
          occurredAt + AUTH_CODE_LIFETIME_SECONDS,
        ),
      prepareAuditEvent(
        c,
        config.db,
        {
          success: true,
          provider: oauthState.provider as 'github' | 'google',
          clientId: oauthState.client_id,
          redirectUri: oauthState.redirect_uri,
          user,
          googleUser,
          userId: identity.userId,
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
    if (oauthState.client_state) {
      redirectUrl.searchParams.set('state', oauthState.client_state)
    }

    return c.redirect(redirectUrl.href)
  }
}

export const handleCallback = createCallbackHandler()
