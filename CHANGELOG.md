# Changelog

`github.com/pocketsign/klon-sdk-go` の変更履歴です。

## Unreleased

- `ClientPrivateKey` による private_key_jwt（ES256）認証を追加しました。認可コード交換・トークン更新・PAR に対応します。

- `github.com/pocketsign/klon-sdk-go` の最初のリリースです。[go-oidc](https://github.com/coreos/go-oidc) と [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2) をベースに、KLON IdP との OIDC 連携を実装するための機能を提供します。
  - `NewClient` / `Client`: 認可 URL の生成、認可コードの交換、トークンの更新を行います。PKCE、nonce、ID トークン、`auth_time` の検証を含みます。
  - `AuthorizeOptions`: スコープ、ACR、prompt、`max_age`、Grant Management、PAR（RFC 9126）の指定に対応します。
  - `AuthorizationDetailInput` ほか: リソースごとの操作を指定する Rich Authorization Requests（RFC 9396）の `authorization_details` を扱います。
  - `TokenSet` / `IDTokenClaims`: 取得したトークンと、デコード済みの ID トークンクレームを提供します。
  - スコープ・ACR・prompt・リソース・Grant Management の各定数を提供します。
