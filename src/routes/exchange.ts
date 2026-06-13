import type { Context } from 'hono'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import { hashAuthToken, verifyClientSecret } from '../lib/crypto'

const BASIC_AUTH_PATTERN = /^Basic ([A-Za-z0-9+/]+={0,2})$/i
const DUMMY_CLIENT_SECRET_HASH = '0'.repeat(64)

type AppContext = Context<{ Bindings: AppBindings }>

interface ClientCredentials {
  clientId: string
  clientSecret: string
}

interface ClientRow {
  client_secret_hash: string
}

interface AuthCodeRow {
  github_id: string
}

interface UserRow {
  github_id: string
  github_login: string
  frozen: number
}

interface AuditEvent {
  success: boolean
  reason?: string
  clientId?: string
  redirectUri?: string
  user?: UserRow
}

function parseBasicCredentials(
  authorization: string | undefined,
): ClientCredentials | null {
  const encodedCredentials = authorization?.match(BASIC_AUTH_PATTERN)?.[1]

  if (!encodedCredentials) {
    return null
  }

  let decodedCredentials: string

  try {
    decodedCredentials = atob(encodedCredentials)
  } catch {
    return null
  }

  const separatorIndex = decodedCredentials.indexOf(':')

  if (separatorIndex <= 0 || separatorIndex === decodedCredentials.length - 1) {
    return null
  }

  return {
    clientId: decodedCredentials.slice(0, separatorIndex),
    clientSecret: decodedCredentials.slice(separatorIndex + 1),
  }
}

function getRequestMetadata(c: AppContext) {
  return {
    ipAddress: c.req.header('CF-Connecting-IP') ?? null,
    userAgent: c.req.header('User-Agent') ?? null,
  }
}

async function recordAuditEvent(
  c: AppContext,
  database: D1Database,
  event: AuditEvent,
  occurredAt: number,
): Promise<void> {
  const { ipAddress, userAgent } = getRequestMetadata(c)

  await database
    .prepare(
      `INSERT INTO auth_events
         (event_type, github_id, github_login, client_id, redirect_uri,
          success, reason, ip_address, user_agent, occurred_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'exchange',
      event.user?.github_id ?? null,
      event.user?.github_login ?? null,
      event.clientId ?? null,
      event.redirectUri ?? null,
      event.success ? 1 : 0,
      event.reason ?? null,
      ipAddress,
      userAgent,
      occurredAt,
    )
    .run()
}

function jsonError(
  c: AppContext,
  error: 'invalid_client' | 'invalid_request' | 'invalid_grant' | 'access_denied',
  status: 400 | 401 | 403,
): Response {
  c.header('Cache-Control', 'no-store')

  if (status === 401) {
    c.header('WWW-Authenticate', 'Basic realm="exchange"')
  }

  return c.json({ error }, status)
}

export async function handleExchange(c: AppContext): Promise<Response> {
  const config = loadAuthServerConfig(c.env)
  const occurredAt = Math.floor(Date.now() / 1000)
  const credentials = parseBasicCredentials(c.req.header('Authorization'))

  if (credentials === null) {
    await recordAuditEvent(
      c,
      config.db,
      { success: false, reason: 'invalid_client' },
      occurredAt,
    )

    return jsonError(c, 'invalid_client', 401)
  }

  const client = await config.db
    .prepare(
      `SELECT client_secret_hash
       FROM clients
       WHERE client_id = ?
         AND disabled_at IS NULL
       LIMIT 1`,
    )
    .bind(credentials.clientId)
    .first<ClientRow>()
  const clientSecretMatches = await verifyClientSecret(
    credentials.clientSecret,
    client?.client_secret_hash ?? DUMMY_CLIENT_SECRET_HASH,
  )

  if (client === null || !clientSecretMatches) {
    await recordAuditEvent(
      c,
      config.db,
      {
        success: false,
        reason: 'invalid_client',
        clientId: credentials.clientId,
      },
      occurredAt,
    )

    return jsonError(c, 'invalid_client', 401)
  }

  const contentType = c.req.header('Content-Type')
  const mediaType = contentType?.split(';', 1)[0]?.trim().toLowerCase()

  if (mediaType !== 'application/x-www-form-urlencoded') {
    await recordAuditEvent(
      c,
      config.db,
      {
        success: false,
        reason: 'invalid_request',
        clientId: credentials.clientId,
      },
      occurredAt,
    )

    return jsonError(c, 'invalid_request', 400)
  }

  let form: FormData

  try {
    form = await c.req.formData()
  } catch {
    await recordAuditEvent(
      c,
      config.db,
      {
        success: false,
        reason: 'invalid_request',
        clientId: credentials.clientId,
      },
      occurredAt,
    )

    return jsonError(c, 'invalid_request', 400)
  }

  const codes = form.getAll('code')
  const redirectUris = form.getAll('redirect_uri')
  const code = codes[0]
  const redirectUri = redirectUris[0]

  if (
    codes.length !== 1 ||
    redirectUris.length !== 1 ||
    typeof code !== 'string' ||
    code.length === 0 ||
    typeof redirectUri !== 'string' ||
    redirectUri.length === 0
  ) {
    await recordAuditEvent(
      c,
      config.db,
      {
        success: false,
        reason: 'invalid_request',
        clientId: credentials.clientId,
        redirectUri:
          typeof redirectUri === 'string' && redirectUri.length > 0
            ? redirectUri
            : undefined,
      },
      occurredAt,
    )

    return jsonError(c, 'invalid_request', 400)
  }

  const codeHash = await hashAuthToken(
    code,
    config.sessionSecret,
    'auth-code',
  )
  const authCode = await config.db
    .prepare(
      `DELETE FROM auth_codes
       WHERE code_hash = ?
         AND client_id = ?
         AND redirect_uri = ?
         AND expires_at > ?
         AND EXISTS (
           SELECT 1
           FROM clients
           WHERE clients.client_id = auth_codes.client_id
             AND clients.disabled_at IS NULL
         )
       RETURNING github_id`,
    )
    .bind(codeHash, credentials.clientId, redirectUri, occurredAt)
    .first<AuthCodeRow>()

  if (authCode === null) {
    await recordAuditEvent(
      c,
      config.db,
      {
        success: false,
        reason: 'invalid_code',
        clientId: credentials.clientId,
        redirectUri,
      },
      occurredAt,
    )

    return jsonError(c, 'invalid_grant', 400)
  }

  const user = await config.db
    .prepare(
      `SELECT users.github_id, users.github_login,
              EXISTS (
                SELECT 1
                FROM frozen_users
                WHERE frozen_users.github_id = users.github_id
              ) AS frozen
       FROM users
       WHERE users.github_id = ?
       LIMIT 1`,
    )
    .bind(authCode.github_id)
    .first<UserRow>()

  if (user === null) {
    await recordAuditEvent(
      c,
      config.db,
      {
        success: false,
        reason: 'invalid_code',
        clientId: credentials.clientId,
        redirectUri,
      },
      occurredAt,
    )

    return jsonError(c, 'invalid_grant', 400)
  }

  if (user.frozen !== 0) {
    await recordAuditEvent(
      c,
      config.db,
      {
        success: false,
        reason: 'frozen_user',
        clientId: credentials.clientId,
        redirectUri,
        user,
      },
      occurredAt,
    )

    return jsonError(c, 'access_denied', 403)
  }

  await recordAuditEvent(
    c,
    config.db,
    {
      success: true,
      clientId: credentials.clientId,
      redirectUri,
      user,
    },
    occurredAt,
  )
  c.header('Cache-Control', 'no-store')

  return c.json({
    github_id: user.github_id,
    github_login: user.github_login,
  })
}
