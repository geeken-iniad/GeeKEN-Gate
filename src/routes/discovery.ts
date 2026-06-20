import type { Context } from 'hono'

import type { AppBindings } from '../lib/config'
import { loadAuthServerConfig } from '../lib/config'
import { buildDiscoveryMetadata } from '../lib/oidc'

type AppContext = Context<{ Bindings: AppBindings }>

export async function handleDiscovery(c: AppContext): Promise<Response> {
  const config = await loadAuthServerConfig(c.env)

  return c.json(buildDiscoveryMetadata(config.issuer))
}
