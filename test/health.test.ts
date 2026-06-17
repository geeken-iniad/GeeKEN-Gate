import { SELF } from 'cloudflare:test'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { app } from '../src/index'
import { allowingRateLimiter } from './rate-limit'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('GET /health', () => {
  it('returns ok when D1 is available', async () => {
    const response = await SELF.fetch('https://example.com/health')

    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toEqual({ status: 'ok' })
  })

  it('returns an error when D1 is unavailable', async () => {
    const database = {
      prepare: vi.fn(() => ({
        first: vi.fn().mockRejectedValue(new Error('D1 unavailable')),
      })),
    } as unknown as D1Database

    const response = await app.request('/health', undefined, {
      DB: database,
      PUBLIC_RATE_LIMITER: allowingRateLimiter,
      CLIENT_RATE_LIMITER: allowingRateLimiter,
    })

    expect(response.status).toBe(503)
    await expect(response.json()).resolves.toEqual({ status: 'error' })
  })

  it('rejects a rate-limited request before querying D1', async () => {
    const database = {
      prepare: vi.fn(),
    } as unknown as D1Database
    const limiter = {
      limit: vi.fn().mockResolvedValue({ success: false }),
    } as RateLimit
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const response = await app.request(
      '/health',
      {
        headers: {
          'CF-Ray': 'health-ray',
        },
      },
      {
        DB: database,
        PUBLIC_RATE_LIMITER: limiter,
        CLIENT_RATE_LIMITER: allowingRateLimiter,
      },
    )

    expect(response.status).toBe(429)
    expect(response.headers.get('cache-control')).toBe('no-store')
    expect(response.headers.get('retry-after')).toBe('60')
    await expect(response.json()).resolves.toEqual({
      error: 'rate_limited',
    })
    expect(limiter.limit).toHaveBeenCalledWith({ key: 'health:global' })
    expect(database.prepare).not.toHaveBeenCalled()
    expect(warn).toHaveBeenCalledWith({
      event: 'rate_limited',
      route: '/health',
      scope: 'global',
      cfRay: 'health-ray',
      clientId: null,
    })
  })

  it('continues when the rate limiter is unavailable', async () => {
    const database = {
      prepare: vi.fn(() => ({
        first: vi.fn().mockResolvedValue({ value: 1 }),
      })),
    } as unknown as D1Database
    const limiter = {
      limit: vi.fn().mockRejectedValue(new Error('limiter unavailable')),
    } as RateLimit
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const response = await app.request(
      '/health',
      {
        headers: {
          'CF-Ray': 'health-ray',
        },
      },
      {
        DB: database,
        PUBLIC_RATE_LIMITER: limiter,
        CLIENT_RATE_LIMITER: allowingRateLimiter,
      },
    )

    expect(response.status).toBe(200)
    expect(database.prepare).toHaveBeenCalledWith('SELECT 1')
    expect(error).toHaveBeenCalledWith({
      event: 'rate_limit_error',
      route: '/health',
      scope: 'global',
      cfRay: 'health-ray',
      clientId: null,
      errorName: 'Error',
    })
  })
})

describe('unknown routes', () => {
  it('returns not found', async () => {
    const response = await SELF.fetch('https://example.com/unknown')

    expect(response.status).toBe(404)
  })

  it('returns not found for removed session routes', async () => {
    const sessionResponse = await SELF.fetch('https://example.com/session')
    const logoutResponse = await SELF.fetch('https://example.com/logout', {
      method: 'POST',
    })

    expect(sessionResponse.status).toBe(404)
    expect(logoutResponse.status).toBe(404)
  })
})
