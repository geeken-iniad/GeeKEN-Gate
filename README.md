# GeeKEN Gate

GitHub Organizationのactive memberだけを認証する、Cloudflare Workers、
Hono、D1ベースの認証サーバーです。

## Requirements

- Node.js 24
- pnpm 11.6.0
- CloudflareアカウントとWranglerログイン
- 試験または運用対象のGitHub Organization
- GitHub OAuth App

## Local Setup

依存関係をインストールし、ローカルD1へmigrationを適用します。

```bash
pnpm install
pnpm db:migrate:local
```

`.dev.vars.example`を基に、Git管理対象外の`.dev.vars`を作成します。

```dotenv
GITHUB_CLIENT_ID=<GitHub OAuth App client ID>
GITHUB_CLIENT_SECRET=<GitHub OAuth App client secret>
GITHUB_ORG=<Organization login>
GITHUB_CALLBACK_URL=http://127.0.0.1:8787/callback
SESSION_SECRET=<32バイト以上のランダム値>
```

`SESSION_SECRET`はUTF-8で32バイト以上を必須とし、短い値は設定読み込み時に
拒否します。次のコマンドで32バイトのランダム値を生成できます。

```bash
openssl rand -hex 32
```

GitHub OAuth Appには次を設定します。

- Homepage URL: `http://127.0.0.1:8787`
- Authorization callback URL: `http://127.0.0.1:8787/callback`
- Device Flow: 無効

Workerを起動します。

```bash
pnpm dev
```

## Client Registration

client IDとredirect URIを指定してclientを登録します。

```bash
pnpm client:register -- --local my-client http://localhost:3000/callback
```

リモートD1へ登録する場合は`--remote`を指定します。

```bash
pnpm client:register -- --remote my-client https://app.example.com/callback
```

このコマンドは以下を行います。

- 32バイトの暗号学的乱数からclient secretを生成する
- DBにはSHA-256 hashだけを保存する
- clientとredirect URIを単一のD1 batchで登録する
- D1登録成功後に限り、平文secretを一度だけ表示する

表示されたsecretは直ちにクライアントバックエンドのsecret managerへ保存して
ください。再表示や復元はできません。redirect URIは登録値と完全一致する必要が
あります。HTTPSを必須とし、ローカル開発時だけloopback HTTPを許可します。

clientを無効化するには次を実行します。

```bash
pnpm exec wrangler d1 execute DB --remote --command \
  "UPDATE clients SET disabled_at = unixepoch() WHERE client_id = 'my-client';"
```

ローカルD1を操作する場合は`--remote`を`--local`へ変更します。

## Login Flow

クライアントバックエンドはブラウザを次のURLへ遷移させます。

```text
http://127.0.0.1:8787/login?client_id=my-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback
```

GitHub認証成功後、登録済みredirect URIへ2分間有効な`code`が付与されます。
クライアントバックエンドはそのcodeを一度だけ交換します。

```bash
curl --request POST http://127.0.0.1:8787/exchange \
  --user 'my-client:<client-secret>' \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'code=<authorization-code>' \
  --data-urlencode 'redirect_uri=http://localhost:3000/callback'
```

成功時はGitHub user情報が返ります。

```json
{
  "github_id": "123456",
  "github_login": "octocat"
}
```

client secretと`/exchange`はクライアントバックエンド専用です。ブラウザやSPAへ
client secretを配布しないでください。

## Production OAuth Smoke Test

デプロイ済みWorker、実GitHub OAuth、リモートD1を通した認証フローは、開発者用
の最小クライアントで手動確認できます。このクライアントは本番アプリでは
ありません。

検証用clientをリモートD1へ登録します。redirect URIは
`http://localhost:3000/callback`を使用します。

```bash
pnpm client:register -- --remote smoke-client http://localhost:3000/callback
```

表示されたclient secretを、Git管理対象外の`.env.smoke`などへ保存します。
client secretをリポジトリへコミットしないでください。

```dotenv
GATE_BASE_URL=https://geeken-gate.example.workers.dev
SMOKE_CLIENT_ID=smoke-client
SMOKE_CLIENT_SECRET=<client:registerで一度だけ表示された値>
SMOKE_REDIRECT_URI=http://localhost:3000/callback
SMOKE_PORT=3000
```

環境変数を読み込んでsmoke clientを起動します。

```bash
set -a
source .env.smoke
set +a
pnpm smoke:client
```

ブラウザで`http://localhost:3000`を開き、`Start GitHub OAuth login`を選択します。
GitHub認証後、結果画面で以下を確認します。

1. 1回目の`/exchange`が成功し、GitHub IDとGitHub loginが表示される
2. 同じcodeを使った2回目の`/exchange`が`invalid_grant`で失敗する
3. client secretがブラウザ、URL、smoke clientのログへ表示されない

`SMOKE_PORT`を変更する場合は、`SMOKE_REDIRECT_URI`のポートとclient登録時の
redirect URIも同じ値へ変更してください。登録済みredirect URIとは完全一致が
必要です。

## Session And Logout

GitHub callback成功時、認証サーバーは7日間有効な`giken_session` Cookieを
設定します。

- `GET /session`: 現在のGitHub userを返す
- `POST /logout`: 認証サーバーのsessionを削除してCookieを失効する

Cookieは`HttpOnly; Secure; SameSite=Lax; Path=/`です。クライアントアプリ自身の
sessionは、クライアント側で別途作成・削除してください。

## User Freeze

GitHub IDを凍結すると、callback、code交換、session照会が拒否されます。

```bash
pnpm exec wrangler d1 execute DB --remote --command \
  "INSERT INTO frozen_users (github_id, frozen_at, reason)
   VALUES ('123456', unixepoch(), 'manual freeze')
   ON CONFLICT (github_id) DO UPDATE SET
     frozen_at = excluded.frozen_at,
     reason = excluded.reason;"
```

凍結解除:

```bash
pnpm exec wrangler d1 execute DB --remote --command \
  "DELETE FROM frozen_users WHERE github_id = '123456';"
```

ローカルD1では`--remote`を`--local`へ変更します。

## Cloudflare Deployment

D1 databaseを作成し、表示されたdatabase IDを`wrangler.jsonc`の
`database_id`へ設定します。

```bash
pnpm exec wrangler login
pnpm exec wrangler d1 create geeken-gate
pnpm db:migrate:remote
```

公開設定は通常のWrangler varsではなくCloudflare Worker secretsとして事前に
登録します。

```bash
pnpm exec wrangler secret put GITHUB_CLIENT_ID
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET
pnpm exec wrangler secret put GITHUB_ORG
pnpm exec wrangler secret put GITHUB_CALLBACK_URL
pnpm exec wrangler secret put SESSION_SECRET
```

GitHub OAuth Appのcallback URLを公開Workerの`/callback`へ変更します。

### GitHub Actions CI/CD

本番デプロイはGitHub Actionsの`.github/workflows/deploy.yml`で実行します。

- `master`へのpull request: validationのみを実行し、Cloudflareへのdeployは行いません。
- `master`へのpush: validation成功後にremote D1 migrationを適用し、Workerをdeployします。
- manual dispatch: 選択refが`refs/heads/master`の場合だけ、pushと同じdeployを実行します。

CIはNode.js 24とpnpm 11.6.0を使用し、各validationで次のコマンドを実行します。

```bash
corepack enable
corepack prepare pnpm@11.6.0 --activate
pnpm install --frozen-lockfile
pnpm check
```

deploy jobはvalidation成功後、remote Cloudflare accountに対して必ず次の順で実行
します。

```bash
pnpm exec wrangler d1 migrations apply DB --remote
pnpm exec wrangler deploy
```

GitHub repository secretsには次を登録してください。値はコミットしたりログへ出力
したりしないでください。

- `CLOUDFLARE_API_TOKEN`: 対象accountでWorkers deployとD1 migrationsに必要な権限を持つCloudflare API token。global API keyは使用しません。
- `CLOUDFLARE_ACCOUNT_ID`: 対象Cloudflare account ID。

Worker runtime secretsはCloudflare側に次を登録済みにしてください。

- `GITHUB_CLIENT_ID`
- `GITHUB_CLIENT_SECRET`
- `GITHUB_ORG`
- `GITHUB_CALLBACK_URL`
- `SESSION_SECRET`

GitHub repository variableとして、deploy後のhealth checkに使う公開Worker URLを
`DEPLOYMENT_URL`へ登録してください。末尾の`/health`は含めません。
例: `https://geeken-gate.example.workers.dev`

deploy後、workflowは次のhealth checkを実行します。

```bash
curl --fail --silent --show-error "$DEPLOYMENT_URL/health"
```

Actions logsでvalidation、remote D1 migrations、`wrangler deploy`、health checkが
成功していることを確認してください。手元からも次のように確認できます。

```bash
curl --fail --silent --show-error "https://geeken-gate.example.workers.dev/health"
```

Cronは毎日UTC 03:00に実行され、期限切れsession、OAuth state、認証codeと、
60日を超えた監査ログを削除します。

## Rate Limiting

Cloudflare Workers Rate Limiting bindingで、公開入口からD1への過剰なアクセスを
抑止します。

- `GET /login`: 接続元IPごとに60回/分
- `POST /exchange`: 接続元IPごとに60回/分
- `POST /exchange`: client secret検証済みclientごとに120回/分
- `GET /health`: Cloudflare拠点ごとに合計60回/分

超過時は`429`、`Retry-After: 60`、`Cache-Control: no-store`と
`{"error":"rate_limited"}`を返します。超過はD1監査ログへ保存せず、`rate_limited`
イベントとしてWorkers Logsへ出力します。Rate Limiting bindingが一時的に
失敗した場合は`rate_limit_error`を記録し、認証処理を継続します。

カウンターはCloudflare拠点単位で、結果整合的に更新されます。厳密な全世界共通
上限ではなく、乱用抑止として扱ってください。閾値は`wrangler.jsonc`の
`ratelimits`で変更できます。

## Verification

```bash
pnpm check
```

実Organizationで確認する場合は、機密リポジトリを持たない試験Organizationと
試験専用OAuth Appを推奨します。以下を確認してください。

1. Organizationのactive memberがログインできる
2. 非所属・pending・凍結userが拒否される
3. codeが一度だけ交換できる
4. `/session`がuserを返し、`/logout`後は401になる
5. D1にGitHub token、平文session、state、code、client secretが存在しない

## Security Notes

- GitHub access tokenはcallback処理中のローカル変数だけで扱います。
- session、OAuth state、認証codeは用途別HMAC-SHA-256だけを保存します。
- client secretはSHA-256 hashだけを保存し、timing-safeに比較します。
- redirect URIはclientごとの登録値と完全一致で検証します。
- CORSは公開していません。
