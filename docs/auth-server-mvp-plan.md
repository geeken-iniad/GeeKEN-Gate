# GitHub Organization 認証サーバー MVP

## Summary

- 空のリポジトリへ Hono + Cloudflare Workers + D1 の TypeScript プロジェクトを新規作成する。
- GitHub OAuth、Organization 所属確認、凍結確認、サーバーサイドセッションを実装する。
- cross-site クライアント向けに、短命な一回限りコードをバックエンド間で交換する confidential client フローを追加する。
- GitHub token、平文 session ID、平文 state、平文認証コード、平文 client secret は永続化しない。

## Interfaces

### `GET /login?client_id=...&redirect_uri=...`

- 有効な client と完全一致登録された redirect URI を確認する。
- 10分有効の state を保存し、`scope=read:org` で GitHub へリダイレクトする。

### `GET /callback?code=...&state=...`

- state を原子的に一度だけ消費する。
- GitHub user と `GET /user/memberships/orgs/{org}` の membership を取得し、`state === "active"` の場合のみ認証成功とする。
- membership が `pending`、取得不能、または OAuth scope 不足の場合は認証を拒否する。
- 凍結確認、user upsert、7日間の auth session、2分間の一回限り認証コードを作成する。
- `giken_session` Cookie を設定し、登録済み redirect URI へ `code` を付けて戻す。

### `POST /exchange`

- `Authorization: Basic base64(client_id:client_secret)` を必須とする。
- `application/x-www-form-urlencoded` の `code` と `redirect_uri` を受け取る。
- client、redirect URI、期限、未使用、未凍結を確認してコードを原子的に消費し、GitHub ID/login を返す。
- client secret を安全に保持できるクライアントバックエンドからのみ呼び出す。ブラウザや SPA から直接呼び出すことは禁止する。

### `GET /session`

- auth ドメインの Cookie セッションを検証し、凍結状態を毎回確認する。

### `POST /logout`

- auth サーバーの session を削除し、`giken_session` Cookie を失効させる。
- クライアントアプリ側 session は削除しない。

callback 失敗は原則 400/403 とする。検証済み state がある場合のみ、登録済み URI へ限定的な `error` コードを付けて戻す。

## Implementation

- `users`、`sessions`、`frozen_users` に加え、`clients`、client 単位の `allowed_redirect_uris`、`oauth_states`、ハッシュ化した `auth_codes`、認証監査ログ用の `auth_events` を migration に定義する。
- session ID、state、code は Web Crypto で32バイト以上生成する。いずれも `SESSION_SECRET` を用いた用途別 HMAC-SHA-256で保存する。
- client secret は人間が指定せず、client 登録時にサーバー側の Web Crypto で32バイト以上の暗号学的乱数から生成する。
- 生成した client secret は URL-safe な文字列として発行時に一度だけ表示し、再表示できないものとする。
- DB には `client_secret_hash` だけを保存し、平文 client secret 用のカラムは設けない。認証時は計算したハッシュを timing-safe な方法で比較する。
- Cookie は `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800` とする。
- GitHub token は callback 内のローカル変数だけで扱い、ログ、DB、Cookie、レスポンスへ出さない。
- D1 はすべて prepared statement を使い、state/code の消費には条件付き `DELETE ... RETURNING` を使用する。
- `GITHUB_CLIENT_ID`、`GITHUB_CLIENT_SECRET`、`GITHUB_ORG`、`GITHUB_CALLBACK_URL`、`SESSION_SECRET`、D1 binding `DB` を型定義・検証する。
- cross-site ブラウザ fetch は採用しないため CORS は公開しない。特に wildcard origin は設定しない。
- MVP では管理 API を実装しない。
- client 登録、secret 生成・ハッシュ化、redirect URI 登録は専用の登録スクリプトで原子的に行い、その手順を README に記載する。
- `frozen_users` 登録は seed script または `wrangler d1 execute` で行い、その手順を README に記載する。
- GitHub API は公式仕様の `read:org` scope と authenticated-user membership endpoint を使用する。
  - [GitHub OAuth Apps authorization](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
  - [OAuth App scopes](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps)
  - [Organization members API](https://docs.github.com/en/rest/orgs/members)

## Audit Log

- `auth_events` を認証監査ログとして使用し、認証処理の event type、成否、失敗理由、GitHub user、client、redirect URI、IP address、User-Agent、発生日時を保存する。
- `auth_events` は追記専用とし、通常処理では既存イベントを更新または個別削除しない。
- user または client の削除後も履歴を保持できるよう、`auth_events` から他テーブルへの外部キーは設定しない。
- IP address は Cloudflare が提供する値を平文の `TEXT` として保存する。
- IP address と User-Agent を含む認証監査ログの保持期間は60日とし、期限を過ぎたイベントは定期クリーンアップで削除する。
- client secret、GitHub token、session ID、state、認証コード、Cookie は監査ログへ記録しない。

## Client Behavior

- クライアントアプリは `/exchange` の成功後、返された GitHub user 情報を基に自身のアプリ用サーバーサイド session を作成する。
- 認証サーバーの `giken_session` Cookie は auth ドメイン専用であり、クライアントアプリから直接読み取らない。
- `/exchange` と client secret の利用はクライアントバックエンドに限定する。client secret をブラウザへ配布しない。
- クライアントアプリからログアウトするときは、まずクライアント自身の session を削除する。
- auth サーバーの共通ログイン状態も終了する場合は、追加で auth サーバーの `/logout` へ遷移または POST する。

## Test Plan

- redirect URI の完全一致、未登録 client、部分一致・悪意ある URI の拒否。
- client secret が平文保存されないこと、および正しい secret と不正な secret の timing-safe 検証。
- client secret がサーバー側で十分なエントロピーを持って生成され、発行時に一度だけ表示されること。
- state/code の期限切れ、再利用、client/redirect URI 不一致の拒否。
- GitHub token交換、user取得、`active` membership の成功、`pending`・非所属・scope不足・GitHub API失敗の拒否。
- 凍結ユーザーの callback、exchange、`/session` 拒否。
- session Cookie属性、DB上のハッシュ保存、期限切れ削除、logout後の無効化。
- auth サーバーの logout がクライアント側 session を変更しないことを確認する。
- 認証の成功・失敗が `auth_events` に保存され、秘密情報が監査ログへ含まれないことを確認する。
- 60日を超えた認証監査ログだけが定期クリーンアップで削除されることを確認する。
- TypeScript型チェック、Workerテスト、ローカルD1 migration、mock GitHub APIによる主要フロー確認。

## Assumptions

- MVP のクライアントは client secret を安全に保持できるバックエンド付きアプリに限定する。SPA/PKCE は対象外。
- クライアント側セッション中の凍結即時反映は対象外で、凍結確認は callback、exchange、authサーバー `/session` で行う。
- JWT、OIDC、ロール・権限管理、管理 API、GitHub token 保存は実装しない。
