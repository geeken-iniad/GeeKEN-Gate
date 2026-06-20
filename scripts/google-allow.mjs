import { createHmac } from 'node:crypto'
import { randomUUID } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { fileURLToPath, pathToFileURL } from 'node:url'
import path from 'node:path'

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
)

export function parseArguments(arguments_) {
  const normalizedArguments = arguments_.filter((argument) => argument !== '--')
  const targetFlags = normalizedArguments.filter(
    (argument) => argument === '--local' || argument === '--remote',
  )
  const remainingArguments = normalizedArguments.filter(
    (argument) => argument !== '--local' && argument !== '--remote',
  )

  if (targetFlags.length !== 1) {
    throw new Error(
      'Usage: pnpm google:allow -- (--local|--remote) --email <email> [--github-id <github-id>]',
    )
  }

  const target = targetFlags[0]
  const emailIndex = remainingArguments.indexOf('--email')
  const githubIdIndex = remainingArguments.indexOf('--github-id')

  if (emailIndex === -1 || emailIndex + 1 >= remainingArguments.length) {
    throw new Error('Missing required argument: --email')
  }

  const email = remainingArguments[emailIndex + 1]
  let githubId

  if (githubIdIndex !== -1) {
    if (githubIdIndex + 1 >= remainingArguments.length) {
      throw new Error('Missing value for --github-id')
    }

    githubId = remainingArguments[githubIdIndex + 1]
  }

  const parsedArguments = {
    target,
    email,
    githubId,
  }
  validateArguments(parsedArguments)

  return parsedArguments
}

export function validateEmail(value) {
  const normalizedEmail = value.trim().toLowerCase()

  if (normalizedEmail.length === 0) {
    throw new Error('Email must not be empty')
  }

  const parts = normalizedEmail.split('@')

  if (
    parts.length !== 2 ||
    parts[0].length === 0 ||
    parts[1].length === 0 ||
    parts[1].includes('@')
  ) {
    throw new Error('Invalid email address')
  }

  return normalizedEmail
}

export function validateGitHubId(value) {
  if (!/^\d+$/.test(value) || Number(value) <= 0) {
    throw new Error('GitHub ID must be a positive integer')
  }

  return value
}

function validateArguments({ email, githubId }) {
  validateEmail(email)

  if (githubId !== undefined) {
    validateGitHubId(githubId)
  }
}

export function hashEmailAddress(email, pepper) {
  if (pepper.length === 0) {
    throw new Error('Email HMAC pepper must not be empty')
  }

  return createHmac('sha256', pepper)
    .update(`email-allowlist\0${email}`)
    .digest('hex')
}

function quoteSql(value) {
  return `'${value.replaceAll("'", "''")}'`
}

export function buildAllowlistSql({
  emailHash,
  pepperVersion,
  userId,
  githubId,
  createdAt,
}) {
  if (githubId !== undefined) {
    return `INSERT INTO users
  (id, created_at, updated_at)
SELECT ${quoteSql(userId)}, ${createdAt}, ${createdAt}
WHERE NOT EXISTS (
  SELECT 1 FROM github_identities WHERE github_id = ${quoteSql(githubId)}
);
INSERT OR IGNORE INTO github_identities
  (github_id, user_id, github_login, created_at, updated_at)
VALUES
  (${quoteSql(githubId)}, ${quoteSql(userId)}, NULL, ${createdAt}, ${createdAt});
INSERT INTO google_login_allowlist
  (email_hash, pepper_version, user_id, created_at)
VALUES
  (
    ${quoteSql(emailHash)},
    ${pepperVersion},
    (SELECT user_id FROM github_identities WHERE github_id = ${quoteSql(githubId)}),
    ${createdAt}
  );`
  }

  return `INSERT INTO users
  (id, created_at, updated_at)
VALUES
  (${quoteSql(userId)}, ${createdAt}, ${createdAt});
INSERT INTO google_login_allowlist
  (email_hash, pepper_version, user_id, created_at)
VALUES
  (${quoteSql(emailHash)}, ${pepperVersion}, ${quoteSql(userId)}, ${createdAt});`
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

function getEmailHashPepper(version, dependencies) {
  const bindingName = `EMAIL_HASH_PEPPER_V${version}`
  const pepper = dependencies[bindingName] ?? process.env[bindingName]

  if (typeof pepper !== 'string' || pepper.length === 0) {
    throw new Error(`${bindingName} is not configured`)
  }

  return pepper
}

export function addToGoogleAllowlist(
  arguments_,
  dependencies = {},
) {
  const { target, email, githubId } = parseArguments(arguments_)
  const normalizedEmail = validateEmail(email)
  const executeWrangler = dependencies.runWrangler ?? runWrangler
  const now = dependencies.now ?? (() => Math.floor(Date.now() / 1000))
  const generateUuid = dependencies.generateUuid ?? randomUUID
  const pepperVersion =
    dependencies.currentPepperVersion ??
    Number(process.env.CURRENT_EMAIL_HASH_PEPPER_VERSION)

  if (!Number.isInteger(pepperVersion) || pepperVersion <= 0) {
    throw new Error('CURRENT_EMAIL_HASH_PEPPER_VERSION is not configured')
  }

  const pepper = getEmailHashPepper(pepperVersion, dependencies)
  const emailHash = hashEmailAddress(normalizedEmail, pepper)
  const userId = generateUuid()
  const sql = buildAllowlistSql({
    emailHash,
    pepperVersion,
    userId,
    githubId,
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
    emailHash,
    pepperVersion,
    userId,
  }
}

function main() {
  try {
    const result = addToGoogleAllowlist(process.argv.slice(2))

    console.log('Google login allowlist entry created successfully.')
    console.log(`Pepper version: ${result.pepperVersion}`)
    console.log('Plaintext email is not stored.')
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
