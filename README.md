# GeeKEN Gate

Cloudflare Workers、Hono、D1 ベースの最小 OIDC Provider です。
GitHub Organization の active member、または手動 allowlist に登録された Google Workspace ユーザーを認証し、標準的な OIDC Authorization Code Flow + PKCE で client に ID Token、access token、refresh token を発行します。

## Requirements

- Node.js 24
- pnpm 11.6.0
- Cloudflare アカウントと Wrangler ログイン
- 試験または運用対象の GitHub Organization
- GitHub OAuth App
- Google OAuth 2.0 credentials（Google login を利用する場合）

## Local Setup

依存関係をインストールし、ローカル D1 へ migration を適用します。

```bash
pnpm install
pnpm db:migrate:local
```

`.dev.vars.example` を基に、Git 管理対象外の `.dev.vars` を作成します。

```dotenv
GITHUB_CLIENT_ID=<GitHub OAuth App client ID>
GITHUB_CLIENT_SECRET=<GitHub OAuth App client secret>
GITHUB_ORG=<Organization login>
GITHUB_CALLBACK_URL=http://127.0.0.1:8787/callback/github
GOOGLE_CLIENT_ID=<Google OAuth client ID>
GOOGLE_CLIENT_SECRET=<Google OAuth client secret>
GOOGLE_CALLBACK_URL=http://127.0.0.1:8787/callback/google
GOOGLE_ALLOWED_HD_DOMAINS=example.com,example.jp
EMAIL_HASH_PEPPER_V1=<32+ byte random secret>
CURRENT_EMAIL_HASH_PEPPER_VERSION=1
OIDC_ISSUER=http://127.0.0.1:8787
OIDC_SIGNING_PRIVATE_KEY=<RSA private JWK JSON for RS256>
OIDC_SIGNING_KEY_ID=<kid>
TOKEN_HASH_SECRET=<32 bytes or longer random secret for token hashes>
```

`OIDC_SIGNING_PRIVATE_KEY` は RS256 署名用の RSA private JWK JSON です。`TOKEN_HASH_SECRET` は state/code/token の HMAC 保存に使用します。`EMAIL_HASH_PEPPER_V1` は Google allowlist 用 email の HMAC に使用します。いずれも session cookie 用ではありません。

GitHub OAuth App には次を設定します。

- Homepage URL: `http://127.0.0.1:8787`
- Authorization callback URL: `http://127.0.0.1:8787/callback/github`
- Device Flow: 無効

Worker を起動します。

```bash
pnpm dev
```

## Public Endpoints

- `GET /.well-known/openid-configuration`
- `GET /jwks.json`
- `GET /authorize`
- `GET /callback/github`
- `GET /callback/google`
- `POST /token`
- `GET /userinfo`
- `POST /userinfo`
- `GET /health`

## Client Registration

client ID と redirect URI を指定して public client を登録します。client secret は生成しません。

```bash
pnpm client:register -- --local my-client http://localhost:3000/callback
```

リモート D1 へ登録する場合は `--remote` を指定します。

```bash
pnpm client:register -- --remote my-client https://app.example.com/callback
```

redirect URI は登録値と完全一致する必要があります。HTTPS を必須とし、ローカル開発時だけ loopback HTTP を許可します。

client を無効化するには次を実行します。

```bash
pnpm exec wrangler d1 execute DB --remote --command \
  "UPDATE clients SET disabled_at = unixepoch() WHERE client_id = 'my-client';"
```

ローカル D1 を操作する場合は `--remote` を `--local` へ変更します。

## Authorization Flow

クライアントはブラウザを `/authorize` へ遷移させます。PKCE パラメータが必須です。

```text
http://127.0.0.1:8787/authorize?client_id=my-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&response_type=code&scope=openid&state=<state>&nonce=<nonce>&code_challenge=<challenge>&code_challenge_method=S256&provider=github
```

`provider` を省略した場合、GitHub と Google を選択できる最小の 2 ボタン画面を表示します。Google ボタンは `openid email` scope で Google 認可を開始します。

GitHub 認証成功後、登録済み redirect URI に 2 分間有効な `code` と元の client `state` が付与されます。クライアントはその code を `/token` で交換します。

```bash
curl --request POST http://127.0.0.1:8787/token \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'client_id=my-client' \
  --data-urlencode 'redirect_uri=http://localhost:3000/callback' \
  --data-urlencode 'code=<authorization-code>' \
  --data-urlencode 'code_verifier=<pkce-verifier>'
```

成功時は以下が返ります。

```json
{
  "access_token": "<opaque>",
  "token_type": "Bearer",
  "expires_in": 900,
  "id_token": "<jwt>",
  "refresh_token": "<opaque>"
}
```

access token は 15 分、refresh token は 30 日間有効です。refresh token は rotation しません。refresh grant では新しい access token と ID Token が返りますが、refresh token は含まれません。

```bash
curl --request POST http://127.0.0.1:8787/token \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=refresh_token' \
  --data-urlencode 'client_id=my-client' \
  --data-urlencode 'refresh_token=<refresh-token>'
```

## UserInfo

access token を Bearer 指定して `/userinfo` を呼びます。

```bash
curl http://127.0.0.1:8787/userinfo \
  --header 'Authorization: Bearer <access-token>'
```

成功時は最小限の claim のみ返します。

```json
{ "sub": "<user_id>" }
```

email、email_hash、GitHub login は返しません。

## Production OAuth Smoke Test

デプロイ済み Worker、実 GitHub OAuth、リモート D1 を通した認証フローは、開発者用の最小クライアントで手動確認できます。このクライアントは本番アプリではありません。

検証用 client をリモート D1 へ登録します。redirect URI は `http://localhost:3000/callback` を使用します。

```bash
pnpm client:register -- --remote smoke-client http://localhost:3000/callback
```

Git 管理対象外の `.env.smoke` などへ以下を保存します。

```dotenv
GATE_BASE_URL=https://geeken-gate.example.workers.dev
SMOKE_CLIENT_ID=smoke-client
SMOKE_REDIRECT_URI=http://localhost:3000/callback
SMOKE_PORT=3000
SMOKE_PROVIDER=github
```

`SMOKE_PROVIDER` は `github`（デフォルト）または `google` を指定できます。Google を試す場合は事前に allowlist 登録が必要です。

環境変数を読み込んで smoke client を起動します。

```bash
set -a
source .env.smoke
set +a
pnpm smoke:client
```

ブラウザで `http://localhost:3000` を開き、`Start OIDC Authorization Code login` を選択します。GitHub 認証後、結果画面で以下を確認します。

1. 1 回目の `/token` が成功し、ID Token と access token が表示される
2. 同じ code を使った 2 回目の `/token` が `invalid_grant` で失敗する
3. access token を使った `/userinfo` が `{ "sub": ... }` を返す
4. code、verifier、access token、refresh token がブラウザと URL に表示されない

## User Freeze

GitHub identity を凍結すると、callback で code が発行されなくなります。

```bash
pnpm exec wrangler d1 execute DB --remote --command \
  "UPDATE github_identities SET frozen_at = unixepoch(), freeze_reason = 'manual freeze' WHERE github_id = '123456';"
```

凍結解除:

```bash
pnpm exec wrangler d1 execute DB --remote --command \
  "UPDATE github_identities SET frozen_at = NULL, freeze_reason = NULL WHERE github_id = '123456';"
```

ローカル D1 では `--remote` を `--local` へ変更します。

## Google Login and Allowlist

Google login は、手動 allowlist に登録された検証済み Google Workspace メールのユーザーを許可する補助経路です。Google OAuth App は Gate 公開 URL の `/callback/google` を authorized redirect URI として登録してください。Google Cloud console 側では `openid` と `email` scope を要求できるように設定します。

許可するメールアドレスを allowlist に登録します。平文 email は保存されず、HMAC 化された `email_hash` と `pepper_version`、紐付く `user_id` のみが保存されます。

```bash
pnpm google:allow -- --local --email user@example.com
```

既存の GitHub identity と同じ `users.id` に紐付けたい場合は `--github-id` を指定します。該当 GitHub identity が存在しなければ、空の `github_login` を持つ新規 GitHub identity が作成されます。

```bash
pnpm google:allow -- --local --email user@example.com --github-id 123456
```

リモート D1 へ登録する場合は `--remote` を指定します。

`GOOGLE_ALLOWED_HD_DOMAINS` はカンマ区切りで許可する `hd`（hosted domain）を指定します。Google ID Token の `email_verified` が `true` で、`hd` が一致し、allowlist に存在しかつ無効化されていない場合のみログインを許可します。

`EMAIL_HASH_PEPPER_V1` は Cloudflare secrets として管理し、リポジトリや vars には平文保存しないでください。pepper rotation 時は `EMAIL_HASH_PEPPER_V2` 等を追加し、`CURRENT_EMAIL_HASH_PEPPER_VERSION` を更新します。allowlist 照合時は DB に存在する `pepper_version` に対応する pepper で HMAC を計算し、登録時は現在のバージョンを使用します。

## Cloudflare Deployment

D1 database を作成し、表示された database ID を `wrangler.jsonc` の `database_id` へ設定します。

```bash
pnpm exec wrangler login
pnpm exec wrangler d1 create geeken-gate-db
pnpm db:migrate:remote
```

公開設定は通常の Wrangler vars ではなく Cloudflare Worker secrets として事前に登録します。

```bash
pnpm exec wrangler secret put GITHUB_CLIENT_ID
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET
pnpm exec wrangler secret put GITHUB_ORG
pnpm exec wrangler secret put GITHUB_CALLBACK_URL
pnpm exec wrangler secret put GOOGLE_CLIENT_ID
pnpm exec wrangler secret put GOOGLE_CLIENT_SECRET
pnpm exec wrangler secret put GOOGLE_CALLBACK_URL
pnpm exec wrangler secret put GOOGLE_ALLOWED_HD_DOMAINS
pnpm exec wrangler secret put EMAIL_HASH_PEPPER_V1
pnpm exec wrangler secret put CURRENT_EMAIL_HASH_PEPPER_VERSION
pnpm exec wrangler secret put OIDC_ISSUER
pnpm exec wrangler secret put OIDC_SIGNING_PRIVATE_KEY
pnpm exec wrangler secret put OIDC_SIGNING_KEY_ID
pnpm exec wrangler secret put TOKEN_HASH_SECRET
```

GitHub OAuth App の callback URL を公開 Worker の `/callback/github`、Google OAuth credentials の authorized redirect URI を `/callback/google` へ設定します。

### GitHub Actions CI/CD

本番デプロイは GitHub Actions の `.github/workflows/deploy.yml` で実行します。

- `master` への pull request: validation のみを実行し、Cloudflare への deploy は行いません。
- `master` への push: validation 成功後に remote D1 migration を適用し、Worker を deploy します。
- manual dispatch: 選択 ref が `refs/heads/master` の場合だけ、push と同じ deploy を実行します。

CI は Node.js 24 と pnpm 11.6.0 を使用し、各 validation で次のコマンドを実行します。

```bash
corepack enable
corepack prepare pnpm@11.6.0 --activate
pnpm install --frozen-lockfile
pnpm check
```

deploy job は validation 成功後、remote Cloudflare account に対して必ず次の順で実行します。

```bash
pnpm exec wrangler d1 migrations apply DB --remote
pnpm exec wrangler deploy
```

GitHub repository secrets には次を登録してください。値はコミットしたりログへ出力したりしないでください。

- `CLOUDFLARE_API_TOKEN`: 対象 account で Workers deploy と D1 migrations に必要な権限を持つ Cloudflare API token。global API key は使用しません。
- `CLOUDFLARE_ACCOUNT_ID`: 対象 Cloudflare account ID。

Worker runtime secrets は Cloudflare 側に次を登録済みにしてください。

- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `GITHUB_ORG`
- `GITHUB_CALLBACK_URL`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_CALLBACK_URL`
- `GOOGLE_ALLOWED_HD_DOMAINS`
- `EMAIL_HASH_PEPPER_V1`
- `CURRENT_EMAIL_HASH_PEPPER_VERSION`
- `OIDC_ISSUER`
- `OIDC_SIGNING_PRIVATE_KEY`
- `OIDC_SIGNING_KEY_ID`
- `TOKEN_HASH_SECRET`

GitHub repository variable として、deploy 後の health check に使う公開 Worker URL を `DEPLOYMENT_URL` へ登録してください。末尾の `/health` は含めません。
例: `https://geeken-gate.example.workers.dev`

deploy 後、workflow は次の health check を実行します。

```bash
curl --fail --silent --show-error "$DEPLOYMENT_URL/health"
```

Actions logs で validation、remote D1 migrations、`wrangler deploy`、health check が成功していることを確認してください。手元からも次のように確認できます。

```bash
curl --fail --silent --show-error "https://geeken-gate.example.workers.dev/health"
```

Cron は毎日 UTC 03:00 に実行され、期限切れ OAuth state、認証 code、access token、refresh token と 60 日を超えた監査ログを削除します。

## Rate Limiting

Cloudflare Workers Rate Limiting binding で、公開入口から D1 への過剰なアクセスを抑止します。

- `GET /authorize`: 接続元 IP ごとに 60 回/分
- `POST /token`: 接続元 IP ごとに 60 回/分
- `POST /token`: `client_id` ごとに 120 回/分
- `GET /health`: Cloudflare 拠点ごとに合計 60 回/分

超過時は `429`、`Retry-After: 60`、`Cache-Control: no-store` と `{"error":"rate_limited"}` を返します。超過は D1 監査ログへ保存せず、`rate_limited` イベントとして Workers Logs へ出力します。Rate Limiting binding が一時的に失敗した場合は `rate_limit_error` を記録し、認証処理を継続します。

カウンターは Cloudflare 拠点単位で、結果整合的に更新されます。厳密な全世界共通上限ではなく、乱用抑止として扱ってください。閾値は `wrangler.jsonc` の `ratelimits` で変更できます。

## Verification

```bash
pnpm check
```

実 Organization で確認する場合は、機密リポジトリを持たない試験 Organization と試験専用 OAuth App を推奨します。以下を確認してください。

1. Organization の active member がログインできる
2. 非所属・pending・凍結 user が拒否される
3. code が一度だけ交換できる
4. refresh token grant が動作し、元の refresh token が継続利用可能
5. `/userinfo` が `sub` のみを返す
6. D1 に GitHub token、平文 state、code、token、client secret、平文 email が存在しない。Google allowlist 用 email HMAC は `google_login_allowlist.email_hash` に保存される

## Security Notes

- GitHub / Google access token は callback 処理中のローカル変数だけで扱います。
- OAuth state、認証 code、access token、refresh token は用途別 HMAC-SHA-256 だけを保存します。
- Google allowlist 用 email は `email_hash`（HMAC-SHA-256）と `pepper_version` のみを保存し、平文 email や email hash をログやレスポンスに出力しません。
- email HMAC pepper は Cloudflare secrets として管理し、リポジトリや Wrangler vars には平文保存しません。
- client secret は生成・保存しません。public client + PKCE を使用します。
- redirect URI は client ごとの登録値と完全一致で検証します。
- ID Token は RS256 で署名します。秘密鍵は Cloudflare secrets として管理します。
- refresh token は rotation せず、30 日の絶対期限、client_id 紐付け、`revoked_at` による失効のみを持ちます。これは browser-based public client における最新 OAuth security guidance に対する意図的な運用例外です。
- CORS は公開していません。
- SPA 側の XSS 対策、token 保存方針、CSP 等は client 側責務とします。

## Scope Notes

この実装では以下をカバーしています。

- OIDC discovery / JWKS / `/authorize` / `/token` / `/userinfo`
- GitHub / Google を上流 IdP とする Authorization Code Flow + PKCE
- RS256 ID Token、opaque access token / refresh token
- public client（client secret なし）
- 新スキーマ（内部 `users.id`、`github_identities`、`google_identities`、`google_login_allowlist`、token テーブル等）
- Google ID Token 検証、`hd` 制限、HMAC email allowlist、identity collision 防止
- `pnpm google:allow` allowlist 登録 CLI
