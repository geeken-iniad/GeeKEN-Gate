import type { Context } from 'hono'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import { buildJwks } from '../lib/oidc'

type AppContext = Context<{ Bindings: AppBindings }>

export async function handleJwks(c: AppContext): Promise<Response> {
  const config = await loadAuthServerConfig(c.env)

  c.header('Cache-Control', 'public, max-age=3600')

  return c.json(buildJwks(config.publicJwk))
}
