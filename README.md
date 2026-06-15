# GeeKEN Gate

GeeKEN Gate is an internal OpenID Connect Provider (OP) for circle applications.
GitHub and Google are external upstream identity providers (IdPs); applications
authenticate through GeeKEN Gate, not directly through GitHub OAuth or Google
OAuth.

The stable application-facing identifier is the GeeKEN Gate OIDC `sub` claim
(`users.user_id`). Applications must not use GitHub user ID, Google `sub`, or
email address as their primary user identifier. GeeKEN Gate handles
authentication and admission; each application handles its own authorization
(roles, permissions, resource access) after it receives GeeKEN Gate `sub`.

## Authentication and admission model

- GeeKEN Gate issues OIDC tokens to registered clients.
- GitHub login verifies GitHub Organization membership before issuing a GeeKEN
  Gate subject.
- Google login verifies the Google ID Token, requires an allowed `hd` hosted
  domain claim, and then checks member database admission.
- Being in the same Google Workspace domain is necessary but not sufficient for
  Google login. The verified email must map to an active admitted member in the
  member DB.
- ID Tokens and `/userinfo` expose GeeKEN Gate `sub`; upstream provider IDs are
  internal audit/linking data only.

## Requirements

- Node.js 24
- pnpm 11
- Cloudflare account and Wrangler login
- D1 database
- GitHub OAuth App for GitHub upstream login
- Google OAuth client for Google upstream login

## OIDC endpoints

Applications should use standard OIDC Authorization Code Flow with PKCE:

- `GET /.well-known/openid-configuration`
- `GET /authorize`
- `POST /token`
- `GET /jwks.json`
- `GET /userinfo`

Operational/session helpers are also available:

- `GET /session`: inspect the current GeeKEN Gate browser session
- `POST /logout`: clear the GeeKEN Gate browser session
- `GET /health`: D1 health check

`/session` is not the primary application integration path. Applications should
use OIDC discovery, `/authorize`, `/token`, and token validation.

## Environment variables

Create `.dev.vars` from `.dev.vars.example` for local development. Important
bindings are:

```dotenv
GITHUB_CLIENT_ID=<GitHub OAuth App client ID>
GITHUB_CLIENT_SECRET=<GitHub OAuth App client secret>
GITHUB_ORG=<Organization login>
GITHUB_CALLBACK_URL=http://127.0.0.1:8787/callback

GOOGLE_CLIENT_ID=<Google OAuth client ID>
GOOGLE_CLIENT_SECRET=<Google OAuth client secret>
GOOGLE_CALLBACK_URL=http://127.0.0.1:8787/callback
GOOGLE_ALLOWED_HD=example.com

SESSION_SECRET=<32 bytes or more random value>
OIDC_ISSUER=http://127.0.0.1:8787
OIDC_PRIVATE_JWK=<P-256 private JWK used to sign ID Tokens>
```

`SESSION_SECRET` must be at least 32 UTF-8 bytes. Generate a local value with:

```bash
openssl rand -hex 32
```

`GOOGLE_ALLOWED_HD` is an exact comma-separated allowlist. It improves account
selection UX when one domain is configured, but the returned Google ID Token
`hd` claim and member DB admission are what decide access.

## Local setup

```bash
pnpm install
pnpm db:migrate:local
pnpm dev
```

Configure both upstream OAuth clients to redirect to the Worker callback URL
(local default: `http://127.0.0.1:8787/callback`).

## Client registration

Register each application client with an exact redirect URI:

```bash
pnpm client:register -- --local my-client http://localhost:3000/callback
```

For remote D1:

```bash
pnpm client:register -- --remote my-client https://app.example.com/callback
```

The command generates a random client secret, stores only its SHA-256 hash, and
prints the plaintext secret exactly once. Store it in the client backend secret
manager. Redirect URIs must match exactly; HTTPS is required except loopback HTTP
for local development.

Disable a client with:

```bash
pnpm exec wrangler d1 execute DB --remote --command \
  "UPDATE clients SET disabled_at = unixepoch() WHERE client_id = 'my-client';"
```

Use `--local` instead of `--remote` for local D1.

## Application integration summary

1. Read `/.well-known/openid-configuration`.
2. Redirect the browser to the discovered `authorization_endpoint` with:
   - `response_type=code`
   - `client_id`
   - exact registered `redirect_uri`
   - `scope=openid`
   - `state`
   - `nonce`
   - `provider=github` or `provider=google`
   - PKCE `code_challenge` and `code_challenge_method=S256`
3. Exchange the callback `code` at the discovered `token_endpoint` using
   `client_secret_basic` and the PKCE `code_verifier`.
4. Fetch `jwks_uri` and verify the ID Token signature and claims (`iss`, `aud`,
   `exp`, `iat`, `auth_time`, `sub`, and `nonce` when sent).
5. Store/link the user by GeeKEN Gate `(iss, sub)`, not by upstream IDs or email.
6. Optionally call `/userinfo` with the access token and require its `sub` to
   match the ID Token `sub`.

## OIDC smoke client

The smoke client exercises the expected integration path: discovery,
Authorization Code + PKCE, provider selection, token exchange, JWKS verification,
GeeKEN Gate `sub` display, and optional `/userinfo` verification.

Register a smoke client with redirect URI `http://localhost:3000/callback`:

```bash
pnpm client:register -- --remote smoke-client http://localhost:3000/callback
```

Create an untracked `.env.smoke`:

```dotenv
GATE_BASE_URL=https://geeken-gate.example.workers.dev
SMOKE_CLIENT_ID=smoke-client
SMOKE_CLIENT_SECRET=<client:register output>
SMOKE_REDIRECT_URI=http://localhost:3000/callback
SMOKE_PORT=3000
SMOKE_PROVIDER=github # or google
SMOKE_USERINFO=true
```

Run it:

```bash
set -a
source .env.smoke
set +a
pnpm smoke:client
```

Open `http://localhost:3000`, choose GitHub or Google, and confirm that the
result page says ID Token verification succeeded and clearly shows `GeeKEN Gate
sub`. The smoke client redacts client secret, authorization code, access token,
and ID Token values from browser output.

## Migrations and deployment

Create or configure the D1 database, apply migrations, set secrets, and deploy:

```bash
pnpm exec wrangler login
pnpm exec wrangler d1 create geeken-gate
pnpm db:migrate:remote

pnpm exec wrangler secret put GITHUB_CLIENT_ID
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET
pnpm exec wrangler secret put GITHUB_ORG
pnpm exec wrangler secret put GITHUB_CALLBACK_URL
pnpm exec wrangler secret put GOOGLE_CLIENT_ID
pnpm exec wrangler secret put GOOGLE_CLIENT_SECRET
pnpm exec wrangler secret put GOOGLE_CALLBACK_URL
pnpm exec wrangler secret put GOOGLE_ALLOWED_HD
pnpm exec wrangler secret put SESSION_SECRET
pnpm exec wrangler secret put OIDC_ISSUER
pnpm exec wrangler secret put OIDC_PRIVATE_JWK

pnpm deploy
```

Cron cleanup runs daily and removes expired sessions, OAuth state, authorization
codes, access tokens, and old audit logs.

## Rate limiting

Cloudflare Workers Rate Limiting protects public entry points:

- `GET /authorize`: source IP scope
- `POST /token`: source IP scope and authenticated client scope
- `GET /health`: global/edge scope

Limit responses use `429`, `Retry-After: 60`, `Cache-Control: no-store`, and
`{"error":"rate_limited"}`. Rate limiter errors are logged and authentication
continues.

## Verification

```bash
pnpm typecheck
pnpm test
pnpm test:ops
pnpm check
```

Manual production checks should confirm active members can log in, non-members
and inactive members are rejected, ID Tokens verify against JWKS, `/userinfo`
`sub` matches the ID Token `sub`, and no plaintext secrets/tokens are persisted
or displayed.

## Security notes

- Client secrets are backend-only and are stored hashed in D1.
- `state`, `nonce`, and PKCE `code_verifier` are per-round-trip values.
- ID Tokens are signed; applications must verify signature and claims.
- Email, GitHub ID, and Google `sub` are not stable application primary keys.
- GitHub/Google access tokens are handled only during upstream callback work.
- CORS is not publicly enabled.
