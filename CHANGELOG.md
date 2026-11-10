# Changelog

## 0.0.2 （2026/11/10）

### その他

- v0.0.1 と同じ内容です。

## 0.0.1 （2026/11/10）

### 新機能

- `github.com/pocketsign/klon-sdk-go` の最初のリリースです。[go-oidc](https://github.com/coreos/go-oidc) と [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2) をベースに、KLON IdP との OIDC 連携を実装するための機能を提供します。
  - `NewClient` / `Client`: 認可 URL の生成、認可コードの交換、トークンの更新を行います。PKCE、nonce、ID トークンの検証を含みます。
  - `AuthorizeOptions`: スコープ、ACR、prompt、`max_age`、Grant Management、PAR（RFC 9126）の指定に対応します。
  - `max_age` は IdP が認可リクエストの時点で判定します。SDK は `auth_time` の経過時間を検証しません。
  - `AuthorizationDetailInput` ほか: リソースごとの操作を指定する Rich Authorization Requests（RFC 9396）の `authorization_details` を扱います。
  - `TokenSet` / `IDTokenClaims`: 取得したトークンと、デコード済みの ID トークンクレームを提供します。
  - スコープ・ACR・prompt・リソース・Grant Management の各定数を提供します。
- `ClientPrivateKey` による private_key_jwt（ES256）認証を追加しました。認可コード交換・トークン更新・PAR に対応します。鍵は標準の `crypto.Signer` で指定でき、ローカルの ECDSA P-256 秘密鍵と KMS 等の署名実装を利用できます。
- `Client.ClientAssertion` を追加しました。SDK が対応していない endpoint でも、SDK と同じ claims の client assertion を利用できます。署名器のエラーは wrap して返すため、`errors.As` で判別できます。
- `Client.RevokeToken`（RFC 7009 トークン失効）を追加しました。
- `AuthorizeOptions.ExtraParams` を追加しました。認可 URL と PAR のどちらでも、任意の追加パラメータを同じ値で送れます。SDK が値を決めるパラメータや、型付きのフィールドで指定するパラメータを指定するとエラーになります。
- `WithIDTokenClaim` / `WithUserinfoClaim` を追加しました。`CreateAuthorizationURL` に渡すと、`claims` パラメータ（OIDC Core 5.5）で要求するクレームを認可 URL と PAR のどちらにも同じ値で送ります。`ExtraParams` の `claims` があればマージします。

### その他

- 動作に必要な Go のバージョンを 1.26.10 以上に上げました。Go 1.26.10 未満には crypto/x509 の脆弱性 GO-2026-6809（CVE-2026-111943）があるためです。古い Go を使っている場合は 1.26.10 以上に更新してください（`GOTOOLCHAIN=local` を設定していなければ、go コマンドが必要なバージョンを自動で取得します）。
