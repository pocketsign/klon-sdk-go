// Package klon は KLON IdP 向けの OIDC クライアント SDK を提供する。
//
// go-oidc と golang.org/x/oauth2 をベースに、KLON 固有のパラメータを
// ラップした高レベル API を提供する。サポートする機能は以下のとおり。
//
//   - ACR values (認証コンテキストクラス)
//   - Authorization Details (RFC 9396 Rich Authorization Requests)
//   - リソーススコープ / リソース定数
//   - PAR (RFC 9126 Pushed Authorization Requests)
//
// 基本的なフローは [Client.CreateAuthorizationURL] で認可 URL を生成し、
// コールバックで [Client.ExchangeCode] によりトークンに交換する。
// 取得したリフレッシュトークンは [Client.RefreshToken] で更新できる。
//
// PKCE は S256 のみをサポートし、利用する grant_type は authorization_code と
// refresh_token のみである。Issuer は環境ごとに異なるため、固定のホスト名を
// 前提とせず [ClientConfig.Issuer] に明示的に設定すること。
package klon
