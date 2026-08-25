# github.com/pocketsign/klon-sdk-go

KLON IdP と連携するための Go SDK。[go-oidc](https://github.com/coreos/go-oidc) と [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2) をベースに、KLON 固有のパラメータ (ACR, Authorization Details, Scope) をサポートする。

## インストール

```bash
go get github.com/pocketsign/klon-sdk-go
```

## クイックスタート

### Confidential Client

```go
package main

import (
	"context"
	"fmt"
	"log"

	klon "github.com/pocketsign/klon-sdk-go"
)

func main() {
	client := klon.NewClient(klon.ClientConfig{
		Issuer:       "https://id.mock.klon.you",
		ClientID:     "your-client-id",
		ClientSecret: "your-client-secret",
		RedirectURI:  "http://localhost:8080/callback",
	})

	// 1. 認可 URL を生成
	boolTrue := true
	authURL, session, err := client.CreateAuthorizationURL(context.Background(), klon.AuthorizeOptions{
		Scopes: []string{klon.ScopeOpenID, klon.ScopeProfile, klon.ScopeOfflineAccess},
		AuthorizationDetails: []klon.AuthorizationDetailInput{
			{
				Identifiers: []string{klon.ResourceMergedFullName},
				Actions:     []klon.ResourceAction{klon.ResourceActionRead},
				Required:    &boolTrue,
			},
		},
		AcrValues: []string{klon.AcrHigh},
		Prompt:    []string{klon.PromptConsent},
		UsePAR:    true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// session をセッションストレージに保存してからリダイレクト
	fmt.Println("Redirect to:", authURL)
	_ = session // セッションストレージに保存

	// 2. コールバックでトークン交換
	// code, state はコールバック URL のクエリパラメータ
	// tokenSet, err := client.ExchangeCode(ctx, code, state, session)

	// 3. トークンリフレッシュ
	// newTokenSet, err := client.RefreshToken(ctx, tokenSet.RefreshToken)
}
```

## API

### OIDC クライアント

#### `NewClient(config ClientConfig) *Client`

```go
type ClientConfig struct {
	Issuer       string // OIDC Issuer URL
	ClientID     string
	ClientSecret string // Confidential Client の場合に指定。空文字列 = Public Client。
	RedirectURI  string
}
```

#### `Client.CreateAuthorizationURL(ctx, opts ...AuthorizeOptions) (*url.URL, *AuthorizationSession, error)`

認可 URL を生成する。返された `session` はコールバック処理に必要なので保存すること。

```go
type AuthorizeOptions struct {
	Scopes                []string                   // デフォルト: ["openid"]
	AuthorizationDetails  []AuthorizationDetailInput // RFC 9396 Rich Authorization Requests
	AcrValues             []string
	Prompt                []string
	MaxAge                *int                       // 認証の最大経過時間 (秒)
	GrantManagementAction GrantManagementAction
	UsePAR                bool                       // RFC 9126 Pushed Authorization Requests
}
```

`MaxAge` を指定した場合、値は `AuthorizationSession` に保存され、`ExchangeCode` 時に ID Token の `auth_time` が検証される。
PAR を使う場合も、`oidc.ClientContext` / `oauth2.HTTPClient` で `ctx` に設定した HTTP client が使用される。

#### `Client.ExchangeCode(ctx, code, state string, session *AuthorizationSession) (*TokenSet, error)`

認可コードをトークンに交換する。`code` と `state` はコールバック URL のクエリパラメータ。PKCE 検証、nonce 検証、ID トークン検証を行う。

```go
tokenSet, err := client.ExchangeCode(ctx, code, state, session)

// デコード済み ID Token クレームにアクセス
fmt.Println(tokenSet.IDTokenClaims.Subject)      // RP 固有のユーザー識別子
fmt.Println(tokenSet.IDTokenClaims.ACR)           // 認証コンテキストクラス
fmt.Println(tokenSet.IDTokenClaims.JPKIVerified)  // JPKI 紐づけ状態
```

#### `Client.RefreshToken(ctx, refreshToken string) (*TokenSet, error)`

リフレッシュトークンでアクセストークンを更新する。レスポンスに新しい ID Token が含まれる場合は署名・issuer・audience・expiry を検証し、成功した場合のみ `IDTokenClaims` もセットされる。

### TokenSet

```go
type TokenSet struct {
    AccessToken          string
    TokenType            string         // 通常 "Bearer"
    ExpiresIn            *int
    RefreshToken         string
    IDToken              string         // 生の JWT 文字列
    IDTokenClaims        *IDTokenClaims // デコード済みクレーム
    Scope                string
    AuthorizationDetails []AuthorizationDetail
}
```

### IDTokenClaims

`ExchangeCode` / `RefreshToken` で取得される ID Token のデコード済みクレーム。

| フィールド | Go 型 | JSON | 説明 | 条件 |
| --- | --- | --- | --- | --- |
| `Issuer` | `string` | `iss` | Issuer (IdP URL) | 常に存在 |
| `Subject` | `string` | `sub` | Subject (RP 固有) | 常に存在 |
| `Audience` | `Audience` | `aud` | Audience (Client ID) | 常に存在 |
| `IssuedAt` | `int64` | `iat` | 発行日時 (Unix epoch) | 常に存在 |
| `Expiry` | `int64` | `exp` | 有効期限 (Unix epoch) | 常に存在 |
| `Nonce` | `string` | `nonce` | Nonce | リクエスト時 |
| `AuthTime` | `int64` | `auth_time` | 認証日時 (Unix epoch) | 常に存在 |
| `ACR` | `string` | `acr` | 認証コンテキストクラス | 常に存在 |
| `AMR` | `[]string` | `amr` | 認証方法 | 常に存在 |
| `SID` | `string` | `sid` | セッション ID | セッション時 |
| `JPKIVerified` | `bool` | `jpki_verified` | JPKI 紐づけ状態 | 常に存在 |
| `Name` | `*string` | `name` | 氏名 | scope: profile |
| `Gender` | `*string` | `gender` | 性別 | scope: profile |
| `Birthdate` | `*string` | `birthdate` | 生年月日 | scope: profile |
| `Email` | `*string` | `email` | メールアドレス | scope: email |
| `EmailVerified` | `*bool` | `email_verified` | メール確認済み | scope: email |
| `Address` | `*string` | `address` | 住所 | scope: address |
| `PhoneNumber` | `*string` | `phone_number` | 電話番号 | scope: phone |
| `PhoneNumberVerified` | `*bool` | `phone_number_verified` | 電話番号確認済み | scope: phone |

### スコープ

`AuthorizeOptions.Scopes` に配列で渡す。ビルダー関数 (`BuildScope`) も利用可能。

| 定数                 | 値               | 説明                 |
| -------------------- | ---------------- | -------------------- |
| `ScopeOpenID`        | `openid`         | OpenID Connect       |
| `ScopeProfile`       | `profile`        | 氏名/生年月日/性別   |
| `ScopeEmail`         | `email`          | メールアドレス       |
| `ScopeOfflineAccess` | `offline_access` | リフレッシュトークン |
| `ScopeAddress`       | `address`        | 住所                 |
| `ScopePhone`         | `phone`          | 電話番号             |
| `ScopePersonalInfo`  | `personal_info`  | 基本4情報            |

### ACR

`AuthorizeOptions.AcrValues` に配列で渡す。

| 定数          | 値                       | 説明                            |
| ------------- | ------------------------ | ------------------------------- |
| `AcrLow`      | `urn:klon:acr:low`       | メールアドレス/外部IdP          |
| `AcrHigh`     | `urn:klon:acr:high`      | JPKI 利用者証明用電子証明書相当 |
| `AcrVeryHigh` | `urn:klon:acr:very_high` | JPKI 署名用電子証明書相当       |

### Prompt

`AuthorizeOptions.Prompt` に配列で渡す。

| 定数            | 値        | 説明                                                     |
| --------------- | --------- | -------------------------------------------------------- |
| `PromptNone`    | `none`    | 認証・認可画面を表示しない。必要な場合はエラー応答する。 |
| `PromptLogin`   | `login`   | エンドユーザーに再認証を要求する                         |
| `PromptConsent` | `consent` | エンドユーザーに明示的な同意を要求する                   |

`none` は他の prompt と併用できない。`login` と `consent` は併用可能。

### Authorization Details (RFC 9396)

`AuthorizeOptions.AuthorizationDetails` に配列で渡す。`Type: "urn:klon:resource_access"` は SDK が自動補完する。

```go
authURL, session, err := client.CreateAuthorizationURL(ctx, klon.AuthorizeOptions{
	AuthorizationDetails: []klon.AuthorizationDetailInput{
		{
			Identifiers: []string{klon.ResourceMergedFullName, klon.ResourceMergedBirthDate},
			Actions:     []klon.ResourceAction{klon.ResourceActionRead},
			Required:    &boolTrue,
		},
		{
			Identifiers: []string{klon.ResourceMergedFullAddress},
			Actions:     []klon.ResourceAction{klon.ResourceActionRead},
			Prefill:     &boolTrue,
		},
	},
})
```

ビルダー関数 (`BuildAuthorizationDetails`) やパーサー (`ParseAuthorizationDetails`) も利用可能。

### Grant Management

`AuthorizeOptions.GrantManagementAction` に指定する。

| 定数                     | 値        | 説明                     |
| ------------------------ | --------- | ------------------------ |
| `GrantManagementCreate`  | `create`  | 新規グラントを作成する   |
| `GrantManagementReplace` | `replace` | 既存グラントを置換する   |
| `GrantManagementMerge`   | `merge`   | 既存グラントにマージする |

### リソース定数

KLON の公式リソースエイリアスが定数として定義されている。

```go
klon.ResourceMergedFullName  // "klon/merged_full_name"
klon.ResourceMergedBirthDate // "klon/merged_birth_date"
klon.ResourceEmailAddress    // "klon/email_address"
```

カテゴリ: `ResourceSigning*` (署名用電子証明書), `ResourceTicket*` (券面事項入力補助AP), `ResourceManual*` (手入力), `ResourceMerged*` (最も信頼性が高い値), `ResourceEmailAddress`, `ResourcePhoneNumber`, `ResourceFaceImage`, 実行リソース (`ResourcePushNotification`, `ResourceAccessCamera`, `ResourceGetCurrentPosition`, `ResourceGetHighAccuracyCurrentPosition`, `ResourceAccessFitnessData`), `ResourceCheckJPKI*` (証明書現況確認)

### ResourceAction

| 定数                   | 値       |
| ---------------------- | -------- |
| `ResourceActionRead`   | `read`   |
| `ResourceActionWrite`  | `write`  |
| `ResourceActionInvoke` | `invoke` |

## 動作環境

- Go 1.25 以降

## ライセンス

[Apache License 2.0](LICENSE)

Copyright 2026 PocketSign, Inc.
