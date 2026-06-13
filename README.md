# GeeKEN Gate

GitHub Organizationのactive memberだけを認証する、Cloudflare Workers、
Hono、D1ベースの認証サーバーです。

## Requirements

- Node.js 24
- pnpm 11
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

`SESSION_SECRET`は次のように生成できます。

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

公開設定は通常のWrangler varsではなくsecretsとして登録します。

```bash
pnpm exec wrangler secret put GITHUB_CLIENT_ID
pnpm exec wrangler secret put GITHUB_CLIENT_SECRET
pnpm exec wrangler secret put GITHUB_ORG
pnpm exec wrangler secret put GITHUB_CALLBACK_URL
pnpm exec wrangler secret put SESSION_SECRET
```

GitHub OAuth Appのcallback URLを公開Workerの`/callback`へ変更してから
デプロイします。

```bash
pnpm deploy
```

Cronは毎日UTC 03:00に実行され、期限切れsession、OAuth state、認証codeと、
60日を超えた監査ログを削除します。

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
