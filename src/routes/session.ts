import type { Context } from 'hono'
import { deleteCookie, getCookie } from 'hono/cookie'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import { hashAuthToken } from '../lib/crypto'

const SESSION_COOKIE_NAME = 'giken_session'

type AppContext = Context<{ Bindings: AppBindings }>

interface SessionUserRow {
  user_id: string
  github_id: string
  github_login: string
  disabled_at: number | null
  member_status: string | null
  disallowed_member_email: number
}

function expireSessionCookie(c: AppContext): void {
  deleteCookie(c, SESSION_COOKIE_NAME, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    path: '/',
  })
}

function sessionError(
  c: AppContext,
  error: 'unauthorized' | 'access_denied',
  status: 401 | 403,
): Response {
  c.header('Cache-Control', 'no-store')

  return c.json({ error }, status)
}

export async function handleSession(c: AppContext): Promise<Response> {
  const session = getCookie(c, SESSION_COOKIE_NAME)

  if (!session) {
    return sessionError(c, 'unauthorized', 401)
  }

  const config = loadAuthServerConfig(c.env)
  const sessionHash = await hashAuthToken(
    session,
    config.sessionSecret,
    'session',
  )
  const currentTime = Math.floor(Date.now() / 1000)
  const user = await config.db
    .prepare(
      `SELECT users.user_id, users.disabled_at,
              members.status AS member_status,
              EXISTS (
                SELECT 1
                FROM external_identities AS email_identities
                INNER JOIN member_emails
                  ON member_emails.normalized_email = lower(trim(email_identities.email))
                 AND member_emails.member_id = users.member_id
                WHERE email_identities.user_id = users.user_id
                  AND member_emails.login_allowed = 0
              ) AS disallowed_member_email,
              external_identities.provider_user_id AS github_id,
              external_identities.provider_login AS github_login
       FROM sessions
       INNER JOIN users
         ON users.user_id = sessions.user_id
       LEFT JOIN members
         ON members.member_id = users.member_id
       LEFT JOIN external_identities
         ON external_identities.user_id = users.user_id
        AND external_identities.provider = 'github'
       WHERE sessions.session_hash = ?
         AND sessions.expires_at > ?
       LIMIT 1`,
    )
    .bind(sessionHash, currentTime)
    .first<SessionUserRow>()

  if (user === null) {
    expireSessionCookie(c)
    return sessionError(c, 'unauthorized', 401)
  }

  if (user.disabled_at !== null) {
    expireSessionCookie(c)
    return sessionError(c, 'access_denied', 403)
  }

  if (user.member_status !== null && user.member_status !== 'active') {
    expireSessionCookie(c)
    return sessionError(c, 'access_denied', 403)
  }

  if (user.disallowed_member_email !== 0) {
    expireSessionCookie(c)
    return sessionError(c, 'access_denied', 403)
  }

  c.header('Cache-Control', 'no-store')

  return c.json({
    user_id: user.user_id,
    github_id: user.github_id,
    github_login: user.github_login,
  })
}

export async function handleLogout(c: AppContext): Promise<Response> {
  const session = getCookie(c, SESSION_COOKIE_NAME)

  if (session) {
    const config = loadAuthServerConfig(c.env)
    const sessionHash = await hashAuthToken(
      session,
      config.sessionSecret,
      'session',
    )

    await config.db
      .prepare(
        `DELETE FROM sessions
         WHERE session_hash = ?`,
      )
      .bind(sessionHash)
      .run()
  }

  expireSessionCookie(c)
  c.header('Cache-Control', 'no-store')

  return c.body(null, 204)
}
