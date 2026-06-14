import type { Context } from 'hono'

import type { AppBindings } from './config'

type AppContext = Context<{ Bindings: AppBindings }>

interface RateLimitContext {
  route: '/login' | '/exchange' | '/health'
  scope: 'ip' | 'client' | 'global'
  clientId?: string
}

function createLogEntry(
  c: AppContext,
  event: 'rate_limited' | 'rate_limit_error',
  context: RateLimitContext,
) {
  return {
    event,
    route: context.route,
    scope: context.scope,
    cfRay: c.req.header('CF-Ray') ?? null,
    clientId: context.clientId ?? null,
  }
}

export function getClientIp(c: AppContext): string {
  return c.req.header('CF-Connecting-IP') ?? 'unknown'
}

export async function enforceRateLimit(
  c: AppContext,
  limiter: RateLimit,
  key: string,
  context: RateLimitContext,
): Promise<Response | null> {
  let success: boolean

  try {
    const outcome = await limiter.limit({ key })
    success = outcome.success
  } catch (error) {
    console.error({
      ...createLogEntry(c, 'rate_limit_error', context),
      errorName: error instanceof Error ? error.name : 'UnknownError',
    })

    return null
  }

  if (success) {
    return null
  }

  console.warn(createLogEntry(c, 'rate_limited', context))
  c.header('Cache-Control', 'no-store')
  c.header('Retry-After', '60')

  return c.json({ error: 'rate_limited' }, 429)
}
