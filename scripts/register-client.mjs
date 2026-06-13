import { randomBytes, createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'
import path from 'node:path'

const CLIENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const LOCAL_HTTP_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]'])
const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
)

export function parseArguments(arguments_) {
  const normalizedArguments = arguments_.filter((argument) => argument !== '--')
  const targetFlags = normalizedArguments.filter(
    (argument) => argument === '--local' || argument === '--remote',
  )
  const positionalArguments = normalizedArguments.filter(
    (argument) => argument !== '--local' && argument !== '--remote',
  )

  if (targetFlags.length !== 1 || positionalArguments.length !== 2) {
    throw new Error(
      'Usage: pnpm client:register -- (--local|--remote) <client-id> <redirect-uri>',
    )
  }

  return {
    target: targetFlags[0],
    clientId: positionalArguments[0],
    redirectUri: positionalArguments[1],
  }
}

export function validateClientId(clientId) {
  if (!CLIENT_ID_PATTERN.test(clientId)) {
    throw new Error(
      'Client ID must be 1-128 characters using letters, numbers, dot, underscore, or hyphen',
    )
  }

  return clientId
}

export function validateRedirectUri(value) {
  let redirectUri

  try {
    redirectUri = new URL(value)
  } catch {
    throw new Error('Redirect URI must be an absolute URL')
  }

  const isLocalHttp =
    redirectUri.protocol === 'http:' &&
    LOCAL_HTTP_HOSTNAMES.has(redirectUri.hostname)

  if (redirectUri.protocol !== 'https:' && !isLocalHttp) {
    throw new Error(
      'Redirect URI must use HTTPS, except for localhost and loopback addresses',
    )
  }

  if (redirectUri.username || redirectUri.password || redirectUri.hash) {
    throw new Error(
      'Redirect URI must not contain credentials or a fragment',
    )
  }

  return redirectUri.href
}

export function generateClientCredential() {
  const clientSecret = randomBytes(32).toString('base64url')
  const clientSecretHash = createHash('sha256')
    .update(clientSecret, 'utf8')
    .digest('hex')

  return { clientSecret, clientSecretHash }
}

function quoteSql(value) {
  return `'${value.replaceAll("'", "''")}'`
}

export function buildRegistrationSql({
  clientId,
  clientSecretHash,
  redirectUri,
  createdAt,
}) {
  return `INSERT INTO clients
  (client_id, client_secret_hash, created_at)
VALUES
  (${quoteSql(clientId)}, ${quoteSql(clientSecretHash)}, ${createdAt});
INSERT INTO allowed_redirect_uris
  (client_id, redirect_uri, created_at)
VALUES
  (${quoteSql(clientId)}, ${quoteSql(redirectUri)}, ${createdAt});`
}

export function runWrangler(arguments_, options = {}) {
  const executable =
    process.platform === 'win32'
      ? path.join(repositoryRoot, 'node_modules', '.bin', 'wrangler.cmd')
      : path.join(repositoryRoot, 'node_modules', '.bin', 'wrangler')
  const result = spawnSync(executable, arguments_, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    stdio: options.captureOutput ? 'pipe' : 'inherit',
  })

  if (result.error) {
    throw result.error
  }

  if (result.status !== 0) {
    throw new Error(`Wrangler exited with status ${result.status}`)
  }

  return result
}

export function registerClient(
  arguments_,
  dependencies = {},
) {
  const { target, clientId, redirectUri } = parseArguments(arguments_)
  const validatedClientId = validateClientId(clientId)
  const validatedRedirectUri = validateRedirectUri(redirectUri)
  const createCredential =
    dependencies.generateClientCredential ?? generateClientCredential
  const executeWrangler = dependencies.runWrangler ?? runWrangler
  const now = dependencies.now ?? (() => Math.floor(Date.now() / 1000))
  const credential = createCredential()
  const sql = buildRegistrationSql({
    clientId: validatedClientId,
    clientSecretHash: credential.clientSecretHash,
    redirectUri: validatedRedirectUri,
    createdAt: now(),
  })

  executeWrangler([
    'd1',
    'execute',
    'DB',
    target,
    '--yes',
    '--command',
    sql,
  ])

  return {
    clientId: validatedClientId,
    clientSecret: credential.clientSecret,
    redirectUri: validatedRedirectUri,
  }
}

function main() {
  try {
    const result = registerClient(process.argv.slice(2))

    console.log('Client registered successfully.')
    console.log(`Client ID: ${result.clientId}`)
    console.log(`Client secret: ${result.clientSecret}`)
    console.log(`Redirect URI: ${result.redirectUri}`)
    console.log('Store the client secret now; it cannot be recovered.')
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error))
    process.exitCode = 1
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  main()
}
