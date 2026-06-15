import type { GitHubAuthenticatedUser } from './github'

export interface ResolvedIdentity {
  userId: string
  disabledAt: number | null
}

export interface UserAdmission {
  allowed: boolean
  reason?: 'disabled_user' | 'member_not_active' | 'member_email_not_allowed'
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
