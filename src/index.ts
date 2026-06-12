import { Hono } from 'hono'

export const app = new Hono<{ Bindings: Env }>()

app.get('/health', async (c) => {
  try {
    await c.env.DB.prepare('SELECT 1').first()

    return c.json({ status: 'ok' })
  } catch {
    return c.json({ status: 'error' }, 503)
  }
})

export default app
