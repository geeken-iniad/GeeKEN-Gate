import { Hono } from 'hono'

import type { AppBindings } from './lib/config'
import { handleCallback } from './routes/callback'
import { handleLogin } from './routes/login'

export const app = new Hono<{ Bindings: AppBindings }>()

app.get('/login', handleLogin)
app.get('/callback', handleCallback)

app.get('/health', async (c) => {
  try {
    await c.env.DB.prepare('SELECT 1').first()

    return c.json({ status: 'ok' })
  } catch {
    return c.json({ status: 'error' }, 503)
  }
})

export default app
