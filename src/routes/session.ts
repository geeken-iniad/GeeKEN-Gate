import type { Context } from 'hono'
import { deleteCookie, getCookie } from 'hono/cookie'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import { hashAuthToken } from '../lib/crypto'

const SESSION_COOKIE_NAME = 'giken_session'

type AppContext = Context<{ Bindings: AppBindings }>

interface SessionUserRow {
  github_id: string
  github_login: string
  frozen: number
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
      `SELECT users.github_id, users.github_login,
              EXISTS (
                SELECT 1
                FROM frozen_users
                WHERE frozen_users.github_id = users.github_id
              ) AS frozen
       FROM sessions
       INNER JOIN users
         ON users.github_id = sessions.github_id
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

  if (user.frozen !== 0) {
    expireSessionCookie(c)
    return sessionError(c, 'access_denied', 403)
  }

  c.header('Cache-Control', 'no-store')

  return c.json({
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
