import type { GitHubAuthenticatedUser } from './github'
import type { GoogleAuthenticatedUser } from './google'

export interface ResolvedIdentity {
  userId: string
  disabledAt: number | null
}

export interface UserAdmission {
  allowed: boolean
  reason?: 'disabled_user' | 'member_not_active' | 'member_email_not_allowed'
}

export type GoogleAdmissionErrorCode =
  | 'member_email_not_found'
  | 'member_login_disabled'
  | 'member_suspended'
  | 'member_left'
  | 'user_disabled'
  | 'google_identity_member_mismatch'

export class GoogleAdmissionError extends Error {
  constructor(public readonly code: GoogleAdmissionErrorCode) {
    super(code)
    this.name = 'GoogleAdmissionError'
  }
}

interface ExistingIdentityRow {
  user_id: string
  disabled_at: number | null
}

interface UserAdmissionRow {
  disabled_at: number | null
  member_status: string | null
  disallowed_member_email: number
}

interface GoogleMemberRow {
  member_id: string
  login_allowed: number
  status: string
}

interface GoogleIdentityRow {
  user_id: string
  member_id: string | null
  disabled_at: number | null
}

interface GoogleIdentityAdmissionRow {
  disabled_at: number | null
  member_status: string | null
  login_allowed: number | null
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase()
}

export async function resolveGitHubIdentity(
  database: D1Database,
  githubUser: GitHubAuthenticatedUser,
  currentTime: number,
): Promise<ResolvedIdentity> {
  const existingIdentity = await database
    .prepare(
      `SELECT users.user_id, users.disabled_at
       FROM external_identities
       INNER JOIN users
         ON users.user_id = external_identities.user_id
       WHERE external_identities.provider = 'github'
         AND external_identities.provider_user_id = ?
       LIMIT 1`,
    )
    .bind(githubUser.githubId)
    .first<ExistingIdentityRow>()

  if (existingIdentity !== null) {
    await database.batch([
      database
        .prepare(
          `UPDATE external_identities
           SET provider_login = ?, updated_at = ?
           WHERE provider = 'github'
             AND provider_user_id = ?`,
        )
        .bind(githubUser.githubLogin, currentTime, githubUser.githubId),
      database
        .prepare(
          `UPDATE users
           SET updated_at = ?
           WHERE user_id = ?`,
        )
        .bind(currentTime, existingIdentity.user_id),
    ])

    return {
      userId: existingIdentity.user_id,
      disabledAt: existingIdentity.disabled_at,
    }
  }

  const userId = crypto.randomUUID()

  await database.batch([
    database
      .prepare(
        `INSERT INTO users
           (user_id, created_at, updated_at)
         VALUES (?, ?, ?)`,
      )
      .bind(userId, currentTime, currentTime),
    database
      .prepare(
        `INSERT INTO external_identities
           (provider, provider_user_id, user_id, provider_login,
            created_at, updated_at)
         VALUES ('github', ?, ?, ?, ?, ?)`,
      )
      .bind(
        githubUser.githubId,
        userId,
        githubUser.githubLogin,
        currentTime,
        currentTime,
      ),
  ])

  return { userId, disabledAt: null }
}

function memberStatusReason(status: string): GoogleAdmissionErrorCode {
  if (status === 'suspended') return 'member_suspended'
  if (status === 'left') return 'member_left'
  return 'member_email_not_found'
}

async function admittedMemberForGoogleEmail(
  database: D1Database,
  email: string,
): Promise<GoogleMemberRow> {
  const row = await database
    .prepare(
      `SELECT member_emails.member_id, member_emails.login_allowed, members.status
       FROM member_emails
       INNER JOIN members
         ON members.member_id = member_emails.member_id
       WHERE member_emails.normalized_email = ?
       LIMIT 1`,
    )
    .bind(normalizeEmail(email))
    .first<GoogleMemberRow>()

  if (row === null) throw new GoogleAdmissionError('member_email_not_found')
  if (row.login_allowed !== 1) throw new GoogleAdmissionError('member_login_disabled')
  if (row.status !== 'active') throw new GoogleAdmissionError(memberStatusReason(row.status))
  return row
}

export async function resolveGoogleIdentity(
  database: D1Database,
  googleUser: GoogleAuthenticatedUser,
  currentTime: number,
): Promise<ResolvedIdentity> {
  const member = await admittedMemberForGoogleEmail(database, googleUser.email)

  const readGoogleIdentity = () => database
    .prepare(
      `SELECT users.user_id, users.member_id, users.disabled_at
       FROM external_identities
       INNER JOIN users
         ON users.user_id = external_identities.user_id
       WHERE external_identities.provider = 'google'
         AND external_identities.provider_user_id = ?
       LIMIT 1`,
    )
    .bind(googleUser.googleSub)
    .first<GoogleIdentityRow>()

  const updateExistingGoogleIdentity = async (identity: GoogleIdentityRow): Promise<ResolvedIdentity> => {
    if (identity.disabled_at !== null) throw new GoogleAdmissionError('user_disabled')
    if (identity.member_id !== member.member_id) {
      throw new GoogleAdmissionError('google_identity_member_mismatch')
    }
    await database.batch([
      database.prepare(
        `UPDATE external_identities
         SET provider_login = ?, email = ?, email_verified = 1, hosted_domain = ?, updated_at = ?
         WHERE provider = 'google' AND provider_user_id = ?`,
      ).bind(googleUser.name ?? googleUser.email, googleUser.email, googleUser.hostedDomain, currentTime, googleUser.googleSub),
      database.prepare(`UPDATE users SET updated_at = ? WHERE user_id = ?`).bind(currentTime, identity.user_id),
    ])
    return { userId: identity.user_id, disabledAt: null }
  }

  const existingIdentity = await readGoogleIdentity()
  if (existingIdentity !== null) {
    return updateExistingGoogleIdentity(existingIdentity)
  }

  const existingUser = await database
    .prepare(
      `SELECT user_id, member_id, disabled_at
       FROM users
       WHERE member_id = ?
       ORDER BY created_at ASC, user_id ASC
       LIMIT 1`,
    )
    .bind(member.member_id)
    .first<GoogleIdentityRow>()

  if (existingUser === null) {
    await database.prepare(
      `INSERT OR IGNORE INTO users (user_id, member_id, created_at, updated_at)
       VALUES (?, ?, ?, ?)`,
    ).bind(crypto.randomUUID(), member.member_id, currentTime, currentTime).run()
  } else {
    if (existingUser.disabled_at !== null) throw new GoogleAdmissionError('user_disabled')
    await database.prepare(`UPDATE users SET updated_at = ? WHERE user_id = ?`).bind(currentTime, existingUser.user_id).run()
  }

  const memberUser = await database
    .prepare(
      `SELECT user_id, member_id, disabled_at
       FROM users
       WHERE member_id = ?
       ORDER BY created_at ASC, user_id ASC
       LIMIT 1`,
    )
    .bind(member.member_id)
    .first<GoogleIdentityRow>()

  if (memberUser === null) throw new GoogleAdmissionError('member_email_not_found')
  if (memberUser.disabled_at !== null) throw new GoogleAdmissionError('user_disabled')

  await database.prepare(
      `INSERT OR IGNORE INTO external_identities
         (provider, provider_user_id, user_id, provider_login, email, email_verified,
          hosted_domain, created_at, updated_at)
       VALUES ('google', ?, ?, ?, ?, 1, ?, ?, ?)`,
    ).bind(
      googleUser.googleSub,
      memberUser.user_id,
      googleUser.name ?? googleUser.email,
      googleUser.email,
      googleUser.hostedDomain,
      currentTime,
      currentTime,
    ).run()

  const resolvedIdentity = await readGoogleIdentity()
  if (resolvedIdentity === null) throw new GoogleAdmissionError('member_email_not_found')
  return updateExistingGoogleIdentity(resolvedIdentity)
}

export async function getUserAdmission(
  database: D1Database,
  userId: string,
): Promise<UserAdmission> {
  const row = await database
    .prepare(
      `SELECT users.disabled_at, members.status AS member_status,
              EXISTS (
                SELECT 1
                FROM external_identities
                INNER JOIN member_emails
                  ON member_emails.normalized_email = lower(trim(external_identities.email))
                 AND member_emails.member_id = users.member_id
                WHERE external_identities.user_id = users.user_id
                  AND member_emails.login_allowed = 0
              ) AS disallowed_member_email
       FROM users
       LEFT JOIN members
         ON members.member_id = users.member_id
       WHERE users.user_id = ?
       LIMIT 1`,
    )
    .bind(userId)
    .first<UserAdmissionRow>()

  if (row === null) {
    return { allowed: false, reason: 'disabled_user' }
  }

  if (row.disabled_at !== null) {
    return { allowed: false, reason: 'disabled_user' }
  }

  if (row.member_status !== null && row.member_status !== 'active') {
    return { allowed: false, reason: 'member_not_active' }
  }

  if (row.disallowed_member_email !== 0) {
    return { allowed: false, reason: 'member_email_not_allowed' }
  }

  return { allowed: true }
}

export async function getGoogleIdentityAdmission(
  database: D1Database,
  userId: string,
  googleSub: string,
): Promise<UserAdmission> {
  const row = await database
    .prepare(
      `SELECT users.disabled_at, members.status AS member_status,
              member_emails.login_allowed
       FROM external_identities
       INNER JOIN users
         ON users.user_id = external_identities.user_id
       LEFT JOIN members
         ON members.member_id = users.member_id
       LEFT JOIN member_emails
         ON member_emails.normalized_email = lower(trim(external_identities.email))
        AND member_emails.member_id = users.member_id
       WHERE external_identities.provider = 'google'
         AND external_identities.provider_user_id = ?
         AND external_identities.user_id = ?
       LIMIT 1`,
    )
    .bind(googleSub, userId)
    .first<GoogleIdentityAdmissionRow>()

  if (row === null || row.disabled_at !== null) {
    return { allowed: false, reason: 'disabled_user' }
  }

  if (row.member_status !== 'active') {
    return { allowed: false, reason: 'member_not_active' }
  }

  if (row.login_allowed !== 1) {
    return { allowed: false, reason: 'member_email_not_allowed' }
  }

  return { allowed: true }
}
