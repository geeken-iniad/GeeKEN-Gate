import { SELF } from 'cloudflare:test'
import { describe, expect, it, vi } from 'vitest'

import { app } from '../src/index'

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

    const response = await app.request('/health', undefined, { DB: database })

    expect(response.status).toBe(503)
    await expect(response.json()).resolves.toEqual({ status: 'error' })
  })
})

describe('unknown routes', () => {
  it('returns not found', async () => {
    const response = await SELF.fetch('https://example.com/unknown')

    expect(response.status).toBe(404)
  })
})
