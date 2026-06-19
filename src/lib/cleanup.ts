const AUTH_EVENT_RETENTION_SECONDS = 60 * 24 * 60 * 60

export async function cleanupExpiredAuthData(
  database: D1Database,
  currentTime: number,
): Promise<void> {
  const authEventCutoff = currentTime - AUTH_EVENT_RETENTION_SECONDS

  await database.batch([
    database
      .prepare(
        `DELETE FROM oauth_states
         WHERE expires_at <= ?`,
      )
      .bind(currentTime),
    database
      .prepare(
        `DELETE FROM auth_codes
         WHERE expires_at <= ?`,
      )
      .bind(currentTime),
    database
      .prepare(
        `DELETE FROM auth_events
         WHERE occurred_at < ?`,
      )
      .bind(authEventCutoff),
  ])
}
