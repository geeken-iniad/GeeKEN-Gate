import { Hono } from 'hono'

import { cleanupExpiredAuthData } from './lib/cleanup'
import type { AppBindings } from './lib/config'
import { enforceRateLimit } from './lib/rate-limit'
import { handleCallback } from './routes/callback'
import { handleExchange } from './routes/exchange'
import { handleLogin } from './routes/login'

export const app = new Hono<{ Bindings: AppBindings }>()

app.get('/login', handleLogin)
app.get('/callback', handleCallback)
app.post('/exchange', handleExchange)

app.get('/health', async (c) => {
  const rateLimitResponse = await enforceRateLimit(
    c,
    c.env.PUBLIC_RATE_LIMITER,
    'health:global',
    { route: '/health', scope: 'global' },
  )

  if (rateLimitResponse !== null) {
    return rateLimitResponse
  }

  try {
    await c.env.DB.prepare('SELECT 1').first()

    return c.json({ status: 'ok' })
  } catch {
    return c.json({ status: 'error' }, 503)
  }
})

export const scheduled: ExportedHandlerScheduledHandler<AppBindings> = async (
  controller,
  env,
) => {
  await cleanupExpiredAuthData(
    env.DB,
    Math.floor(controller.scheduledTime / 1000),
  )
}

export default {
  fetch: app.fetch,
  scheduled,
} satisfies ExportedHandler<AppBindings>
