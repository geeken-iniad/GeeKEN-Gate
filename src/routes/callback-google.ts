import type { Context, Handler } from 'hono'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import {
  generateRandomToken,
  hashAuthToken,
  normalizeEmail,
  verifyHashedToken,
} from '../lib/crypto'
import {
  authenticateGoogleUser,
  canonicalizeGoogleIssuer,
  GoogleAuthError,
  type GoogleAuthenticatedUser,
  type GoogleAuthOptions,
} from '../lib/google'
import { hashEmailAddress } from '../lib/crypto'

const AUTH_CODE_LIFETIME_SECONDS = 2 * 60
const GOOGLE_AUTH_ERROR = 'access_denied'

type AppContext = Context<{ Bindings: AppBindings }>
type AuthenticateGoogleUser = typeof authenticateGoogleUser

interface OAuthStateRow {
  client_state: string
  client_id: string
  redirect_uri: string
  nonce: string
  code_challenge: string
  upstream_state_hash: string
}

interface AllowlistRow {
  email_hash: string
  pepper_version: number
  user_id: string
  disabled_at: number | null
}

interface AuditEvent {
  success: boolean
  provider: string
  userId?: string
  reason?: string
  clientId?: string
  redirectUri?: string
  googleIssuer?: string
  googleSub?: string
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
         (event_type, provider, user_id, google_issuer, google_sub, client_id,
          redirect_uri, success, reason, ip_address, user_agent, occurred_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'callback',
      event.provider,
      event.userId ?? null,
      event.googleIssuer ?? null,
      event.googleSub ?? null,
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
  error = GOOGLE_AUTH_ERROR,
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

async function computeEmailHashes(
  normalizedEmail: string,
  peppers: Map<number, string>,
): Promise<{ version: number; hash: string }[]> {
  return Promise.all(
    Array.from(peppers.entries()).map(async ([version, pepper]) => ({
      version,
      hash: await hashEmailAddress(normalizedEmail, pepper),
    })),
  )
}

async function findAllowlistRow(
  database: D1Database,
  normalizedEmail: string,
  peppers: Map<number, string>,
): Promise<AllowlistRow | null> {
  const hashes = await computeEmailHashes(normalizedEmail, peppers)
  const placeholders = hashes.map(() => '?').join(', ')
  const rows = await database
    .prepare(
      `SELECT email_hash, pepper_version, user_id, disabled_at
       FROM google_login_allowlist
       WHERE email_hash IN (${placeholders})`,
    )
    .bind(...hashes.map(({ hash }) => hash))
    .all<AllowlistRow>()

  for (const row of rows.results) {
    const computed = hashes.find(({ version }) => version === row.pepper_version)

    if (
      computed !== undefined &&
      computed.hash === row.email_hash &&
      row.disabled_at === null
    ) {
      return row
    }
  }

  return null
}

function buildGoogleAuthOptions(
  config: Awaited<ReturnType<typeof loadAuthServerConfig>>,
): GoogleAuthOptions {
  return {
    clientId: config.googleClientId,
    clientSecret: config.googleClientSecret,
    callbackUrl: config.googleCallbackUrl,
    allowedHdDomains: config.googleAllowedHdDomains,
  }
}

export function createGoogleCallbackHandler(
  authenticate: AuthenticateGoogleUser = authenticateGoogleUser,
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
        { success: false, provider: 'google', reason: 'invalid_request' },
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
           AND provider = 'google'
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
        { success: false, provider: 'google', reason: 'invalid_state' },
        occurredAt,
      )

      c.header('Cache-Control', 'no-store')
      return c.json({ error: 'invalid_request' }, 400)
    }

    let user: GoogleAuthenticatedUser

    try {
      user = await authenticate(code, buildGoogleAuthOptions(config))
    } catch (error) {
      const reason =
        error instanceof GoogleAuthError ? error.code : 'google_auth_failed'

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

      return redirectWithError(
        oauthState.redirect_uri,
        oauthState.client_state,
      )
    }

    const canonicalIssuer = canonicalizeGoogleIssuer(user.issuer)
    const normalizedEmail = normalizeEmail(user.email)
    const allowlistRow = await findAllowlistRow(
      config.db,
      normalizedEmail,
      config.emailHashPeppers,
    )

    if (allowlistRow === null) {
      await recordAuditEvent(
        c,
        config.db,
        {
          success: false,
          provider: 'google',
          reason: 'not_in_allowlist',
          clientId: oauthState.client_id,
          redirectUri: oauthState.redirect_uri,
          googleIssuer: canonicalIssuer,
          googleSub: user.sub,
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
        `SELECT user_id
         FROM google_identities
         WHERE google_issuer = ?
           AND google_sub = ?
         LIMIT 1`,
      )
      .bind(canonicalIssuer, user.sub)
      .first<{ user_id: string }>()

    if (identity !== null && identity.user_id !== allowlistRow.user_id) {
      await recordAuditEvent(
        c,
        config.db,
        {
          success: false,
          provider: 'google',
          reason: 'identity_collision',
          userId: identity.user_id,
          clientId: oauthState.client_id,
          redirectUri: oauthState.redirect_uri,
          googleIssuer: canonicalIssuer,
          googleSub: user.sub,
        },
        occurredAt,
      )

      return redirectWithError(
        oauthState.redirect_uri,
        oauthState.client_state,
      )
    }

    if (identity !== null) {
      await config.db
        .prepare(
          `UPDATE google_identities
           SET last_seen_at = ?
           WHERE google_issuer = ?
             AND google_sub = ?`,
        )
        .bind(occurredAt, canonicalIssuer, user.sub)
        .run()
    } else {
      await config.db
        .prepare(
          `INSERT INTO google_identities
             (google_issuer, google_sub, user_id, created_at, last_seen_at)
           VALUES (?, ?, ?, ?, ?)`,
        )
        .bind(canonicalIssuer, user.sub, allowlistRow.user_id, occurredAt, occurredAt)
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
          allowlistRow.user_id,
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
          provider: 'google',
          userId: allowlistRow.user_id,
          clientId: oauthState.client_id,
          redirectUri: oauthState.redirect_uri,
          googleIssuer: canonicalIssuer,
          googleSub: user.sub,
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

export const handleCallbackGoogle = createGoogleCallbackHandler()
