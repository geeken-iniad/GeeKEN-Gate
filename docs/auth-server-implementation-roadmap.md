# 認証サーバー MVP 暫定実装手順

この文書は、`docs/auth-server-mvp-plan.md` に定義した MVP を実装するまでの
当面の作業順序を示す。設計判断や要件が変わった場合は、実装を続ける前に
この手順を更新する。

各作業項目は原則として単独のコミットにする。実装と検証が完了した時点で
コミット対象、変更概要、検証結果、コミットメッセージ案を提示し、承認後に
その作業項目だけをコミットして次へ進む。

## 依存関係と実施順序

1. 実行環境設定の型定義と検証
2. `GET /login`
3. GitHub API クライアント
4. `GET /callback`
5. `POST /exchange`
6. `GET /session` と `POST /logout`
7. 定期クリーンアップ
8. 運用スクリプトと README

暗号ユーティリティと D1 スキーマは実装済みであり、以降の作業はこれらを
前提とする。`GET /callback` は `GET /login` と GitHub API クライアントに
依存し、それ以降のエンドポイントは callback が作成する認証情報に依存する。

## 1. 実行環境設定の型定義と検証

- 目的: GitHub OAuth 設定と `SESSION_SECRET` の欠落や不正値を処理開始前に
  検出する。
- 変更範囲: Env 型、設定読み込みモジュール、単体テスト。
- 完了条件: `GITHUB_CLIENT_ID`、`GITHUB_CLIENT_SECRET`、`GITHUB_ORG`、
  `GITHUB_CALLBACK_URL`、`SESSION_SECRET`、D1 binding `DB` が型付けされ、
  必須文字列の欠落や空文字が拒否される。
- 検証方法: 正常な設定、各設定の欠落、空文字、不正な callback URL に対する
  単体テスト、型チェック、全テスト。
- 想定コミット範囲: 環境設定とそのテストのみ。
- コミットメッセージ案: `feat: 認証サーバーの環境設定を検証`

## 2. `GET /login`

- 目的: client と redirect URI を検証し、安全な OAuth state を発行して
  GitHub 認可画面へ遷移させる。
- 変更範囲: login ルート、client 検索、state の生成・保存、ルートテスト。
- 完了条件: 有効な client と完全一致する登録済み redirect URI の場合だけ、
  10 分有効の state を保存し、`scope=read:org` を指定して GitHub へ
  リダイレクトする。DB には state の用途別 HMAC だけを保存する。
- 検証方法: 正常系、未登録・無効化済み client、部分一致や悪意ある URI、
  state の有効期限、平文 state 非保存をテストする。
- 想定コミット範囲: login 処理とそのテストのみ。
- コミットメッセージ案: `feat: GitHub OAuth ログイン開始処理を追加`

## 3. GitHub API クライアント

- 目的: OAuth code の token 交換、GitHub user 取得、Organization membership
  取得を HTTP ルートから分離する。
- 変更範囲: GitHub API クライアント、レスポンス型、mock HTTP テスト。
- 完了条件: access token をローカル変数内だけで扱い、user と membership を
  型検証する。membership は `active` の場合だけ成功として扱う。
- 検証方法: token 交換、user 取得、active・pending・非所属・scope 不足、
  GitHub エラー、不正レスポンスを mock でテストする。
- 想定コミット範囲: GitHub API 通信層とそのテストのみ。
- コミットメッセージ案: `feat: GitHub 認証 API クライアントを追加`

## 4. `GET /callback`

- 目的: GitHub OAuth callback を検証し、認証サーバー session と一回限りの
  認証 code を発行する。
- 変更範囲: callback ルート、state の原子的消費、凍結確認、user upsert、
  session・code 発行、Cookie、監査ログ、ルートテスト。
- 完了条件: state を `DELETE ... RETURNING` で一度だけ消費し、Organization
  membership と凍結状態を確認する。成功時は 7 日間の session、2 分間の
  code、所定属性の `giken_session` Cookie を発行する。
- 検証方法: 成功、state 再利用・期限切れ、GitHub 失敗、非 active membership、
  凍結ユーザー、Cookie 属性、秘密情報非永続化、成功・失敗監査をテストする。
- 想定コミット範囲: callback フローとそのテストのみ。
- コミットメッセージ案: `feat: GitHub OAuth コールバック処理を追加`

## 5. `POST /exchange`

- 目的: confidential client が一回限りの認証 code を GitHub user 情報へ
  交換できるようにする。
- 変更範囲: Basic 認証、form 検証、code の原子的消費、凍結確認、監査ログ、
  ルートテスト。
- 完了条件: client secret、client、redirect URI、有効期限、未使用、未凍結を
  検証し、成功時に GitHub ID と login を返す。
- 検証方法: 正常系、不正・欠落 Basic 認証、不正 content type、client や
  redirect URI の不一致、期限切れ、再利用、凍結をテストする。
- 想定コミット範囲: code 交換処理とそのテストのみ。
- コミットメッセージ案: `feat: 認証コード交換エンドポイントを追加`

## 6. `GET /session` と `POST /logout`

- 目的: auth ドメインの共通ログイン状態を照会し、終了できるようにする。
- 変更範囲: Cookie 解析、session 検証、凍結確認、session 削除、Cookie 失効、
  ルートテスト。
- 完了条件: `/session` は有効かつ未凍結の user だけを返す。`/logout` は
  auth session を削除して Cookie を失効させ、クライアント側 session には
  関与しない。
- 検証方法: 正常系、Cookie 欠落、期限切れ、凍結、logout 後の無効化、
  Cookie 失効属性をテストする。
- 想定コミット範囲: session 照会・logout とそのテストのみ。
- コミットメッセージ案: `feat: 認証セッション管理エンドポイントを追加`

## 7. 定期クリーンアップ

- 目的: 不要になった認証情報と保持期限を超えた監査ログを削除する。
- 変更範囲: Scheduled handler、Wrangler cron 設定、クリーンアップテスト。
- 完了条件: 期限切れ session・state・code と、60 日を超えた `auth_events`
  だけを削除する。
- 検証方法: 境界時刻の前後、未期限切れデータの保持、対象テーブルごとの削除を
  テストする。
- 想定コミット範囲: 定期削除処理、cron 設定、そのテストのみ。
- コミットメッセージ案: `feat: 認証データの定期クリーンアップを追加`

## 8. 運用スクリプトと README

- 目的: client 登録、secret 発行、redirect URI 登録、ユーザー凍結を安全かつ
  再現可能に運用する。
- 変更範囲: client 登録スクリプト、必要な package scripts、README。
- 完了条件: client と redirect URI を原子的に登録し、32 バイト以上の
  client secret を生成して一度だけ表示する。DB には hash だけを保存する。
  凍結・解除、migration、ローカル起動、secret 設定の手順を文書化する。
- 検証方法: ローカル D1 で登録成功、重複・不正 URI 時のロールバック、
  平文 secret 非保存、記載コマンドの動作を確認する。
- 想定コミット範囲: 運用スクリプト、package scripts、README のみ。
- コミットメッセージ案: `docs: 認証サーバーの運用手順を追加`

## 対象外

MVP では SPA/PKCE、JWT、OIDC、ロール・権限管理、管理 API、GitHub token の
永続化、cross-site browser fetch 用 CORS を実装しない。
