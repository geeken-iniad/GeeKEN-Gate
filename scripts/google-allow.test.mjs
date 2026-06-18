import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { describe, it } from 'node:test'

import {
  addToGoogleAllowlist,
  buildAllowlistSql,
  hashEmailAddress,
  parseArguments,
  validateEmail,
  validateGitHubId,
} from './google-allow.mjs'

const MINIMAL_SCHEMA_SQL = `
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE github_identities (
  github_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  github_login TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE google_login_allowlist (
  email_hash TEXT NOT NULL,
  pepper_version INTEGER NOT NULL,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (email_hash, pepper_version)
);
`

function expectedEmailHash(email, pepper) {
  return createHmac('sha256', pepper)
    .update(`email-allowlist\0${email.trim().toLowerCase()}`)
    .digest('hex')
}

describe('google-allow operations', () => {
  it('adds an allowlist entry for a new user', () => {
    const calls = []
    const result = addToGoogleAllowlist(
      ['--local', '--email', 'User@Example.COM'],
      {
        now: () => 1_800_000_000,
        generateUuid: () => 'new-user-uuid',
        EMAIL_HASH_PEPPER_V1: 'pepper-secret',
        currentPepperVersion: 1,
        runWrangler: (arguments_) => {
          calls.push(arguments_)
        },
      },
    )

    assert.equal(result.emailHash, expectedEmailHash('User@Example.COM', 'pepper-secret'))
    assert.equal(result.pepperVersion, 1)
    assert.equal(result.userId, 'new-user-uuid')
    assert.equal(calls.length, 1)
    assert.deepEqual(calls[0].slice(0, 6), [
      'd1',
      'execute',
      'DB',
      '--local',
      '--yes',
      '--command',
    ])
    const sql = calls[0][6]
    assert.match(sql, /INSERT INTO users/)
    assert.match(sql, /INSERT INTO google_login_allowlist/)
    assert.doesNotMatch(sql, /user@example\.com/)
    assert.doesNotMatch(sql, /User@Example\.COM/)
    assert.doesNotMatch(sql, /github_identities/)
  })

  it('links to an existing or new GitHub identity', () => {
    const calls = []
    const result = addToGoogleAllowlist(
      [
        '--remote',
        '--email',
        'user@example.com',
        '--github-id',
        '123456',
      ],
      {
        now: () => 1_800_000_000,
        generateUuid: () => 'new-user-uuid',
        EMAIL_HASH_PEPPER_V2: 'pepper-secret',
        currentPepperVersion: 2,
        runWrangler: (arguments_) => {
          calls.push(arguments_)
        },
      },
    )

    assert.equal(result.pepperVersion, 2)
    assert.equal(calls.length, 1)
    const sql = calls[0][6]
    assert.match(sql, /github_identities/)
    assert.match(sql, /github_id = '123456'/)
    assert.match(sql, /github_login/)
    assert.match(sql, /\bNULL\b/)
    assert.match(sql, /INSERT OR IGNORE INTO github_identities/)
    assert.match(sql, /WHERE NOT EXISTS \(\s*SELECT 1 FROM github_identities/)
  })

  it('requires an email', () => {
    assert.throws(
      () => addToGoogleAllowlist(['--local'], {}),
      /Missing required argument: --email/,
    )
  })

  it('does not call D1 when validation fails', () => {
    let called = false

    assert.throws(() =>
      addToGoogleAllowlist(
        ['--local', '--email', 'not-an-email'],
        {
          runWrangler: () => {
            called = true
          },
        },
      ),
    )
    assert.equal(called, false)
  })

  it('throws when pepper is missing', () => {
    assert.throws(
      () =>
        addToGoogleAllowlist(['--local', '--email', 'user@example.com'], {
          currentPepperVersion: 1,
        }),
      /EMAIL_HASH_PEPPER_V1 is not configured/,
    )
  })

  it('throws when pepper version is missing or invalid', () => {
    assert.throws(
      () =>
        addToGoogleAllowlist(['--local', '--email', 'user@example.com'], {
          EMAIL_HASH_PEPPER_V1: 'pepper-secret',
        }),
      /CURRENT_EMAIL_HASH_PEPPER_VERSION is not configured/,
    )
  })

  it('normalizes and validates emails', () => {
    assert.equal(validateEmail('  User@Example.COM  '), 'user@example.com')
    assert.throws(() => validateEmail(''), /Email must not be empty/)
    assert.throws(() => validateEmail('not-an-email'), /Invalid email address/)
    assert.throws(() => validateEmail('@example.com'), /Invalid email address/)
    assert.throws(() => validateEmail('user@'), /Invalid email address/)
  })

  it('validates GitHub IDs', () => {
    assert.equal(validateGitHubId('123456'), '123456')
    assert.throws(() => validateGitHubId('abc'), /GitHub ID must be a positive integer/)
    assert.throws(() => validateGitHubId('0'), /GitHub ID must be a positive integer/)
  })

  it('parses arguments with optional GitHub ID', () => {
    assert.deepEqual(
      parseArguments([
        '--',
        '--local',
        '--email',
        'user@example.com',
        '--github-id',
        '123456',
      ]),
      {
        target: '--local',
        email: 'user@example.com',
        githubId: '123456',
      },
    )

    assert.deepEqual(
      parseArguments(['--', '--remote', '--email', 'user@example.com']),
      {
        target: '--remote',
        email: 'user@example.com',
        githubId: undefined,
      },
    )
  })

  it('requires exactly one target', () => {
    assert.throws(
      () => parseArguments(['--email', 'user@example.com']),
      /Usage:/,
    )
    assert.throws(
      () =>
        parseArguments([
          '--local',
          '--remote',
          '--email',
          'user@example.com',
        ]),
      /Usage:/,
    )
  })

  it('escapes SQL string values', () => {
    const sql = buildAllowlistSql({
      emailHash: "a'b",
      pepperVersion: 1,
      userId: "u'id",
      githubId: "g'id",
      createdAt: 1_800_000_000,
    })

    assert.match(sql, /a''b/)
    assert.match(sql, /u''id/)
    assert.match(sql, /g''id/)
  })

  it('produces a deterministic email hash', () => {
    const firstHash = hashEmailAddress('user@example.com', 'pepper-secret')
    const secondHash = hashEmailAddress('user@example.com', 'pepper-secret')
    const differentPepper = hashEmailAddress('user@example.com', 'other-pepper')

    assert.equal(firstHash, secondHash)
    assert.notEqual(firstHash, differentPepper)
    assert.match(firstHash, /^[0-9a-f]{64}$/)
  })

  it('uses the pepper matching the configured current version (version 2)', () => {
    const calls = []
    const result = addToGoogleAllowlist(
      ['--local', '--email', 'user@example.com'],
      {
        now: () => 1_800_000_000,
        generateUuid: () => 'new-user-uuid',
        EMAIL_HASH_PEPPER_V2: 'pepper-v2-secret',
        currentPepperVersion: 2,
        runWrangler: (arguments_) => {
          calls.push(arguments_)
        },
      },
    )

    assert.equal(result.emailHash, expectedEmailHash('user@example.com', 'pepper-v2-secret'))
    assert.equal(result.pepperVersion, 2)
  })

  it('uses the pepper matching the configured current version (version 3)', () => {
    const calls = []
    const result = addToGoogleAllowlist(
      ['--local', '--email', 'user@example.com'],
      {
        now: () => 1_800_000_000,
        generateUuid: () => 'new-user-uuid',
        EMAIL_HASH_PEPPER_V3: 'pepper-v3-secret',
        currentPepperVersion: 3,
        runWrangler: (arguments_) => {
          calls.push(arguments_)
        },
      },
    )

    assert.equal(result.emailHash, expectedEmailHash('user@example.com', 'pepper-v3-secret'))
    assert.equal(result.pepperVersion, 3)
  })

  it('throws when the current version pepper is missing', () => {
    assert.throws(
      () =>
        addToGoogleAllowlist(['--local', '--email', 'user@example.com'], {
          EMAIL_HASH_PEPPER_V1: 'pepper-secret',
          currentPepperVersion: 2,
        }),
      /EMAIL_HASH_PEPPER_V2 is not configured/,
    )
  })

  it('executes the --github-id SQL against SQLite', () => {
    const sql = buildAllowlistSql({
      emailHash: 'a'.repeat(64),
      pepperVersion: 2,
      userId: 'new-user-uuid',
      githubId: '123456',
      createdAt: 1_800_000_000,
    })
    const result = spawnSync('sqlite3', [':memory:'], {
      input: `${MINIMAL_SCHEMA_SQL}\n${sql}\nSELECT user_id FROM google_login_allowlist;`,
      encoding: 'utf8',
    })

    assert.equal(result.status, 0, `SQLite error: ${result.stderr}`)
    assert.equal(result.stdout.trim(), 'new-user-uuid')
  })

  it('uses an existing GitHub identity user_id in the --github-id SQL', () => {
    const existingUserId = 'existing-user-uuid'
    const seedSql = `
INSERT INTO users (id, created_at, updated_at) VALUES ('${existingUserId}', 1700000000, 1700000000);
INSERT INTO github_identities (github_id, user_id, github_login, created_at, updated_at)
VALUES ('123456', '${existingUserId}', NULL, 1700000000, 1700000000);
`
    const sql = buildAllowlistSql({
      emailHash: 'a'.repeat(64),
      pepperVersion: 2,
      userId: 'new-user-uuid',
      githubId: '123456',
      createdAt: 1_800_000_000,
    })
    const result = spawnSync('sqlite3', [':memory:'], {
      input: `${MINIMAL_SCHEMA_SQL}\n${seedSql}\n${sql}\nSELECT user_id FROM google_login_allowlist;`,
      encoding: 'utf8',
    })

    assert.equal(result.status, 0, `SQLite error: ${result.stderr}`)
    assert.equal(result.stdout.trim(), existingUserId)
  })
})
