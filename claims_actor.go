package klon

// WithActor は claims パラメータで、代理登録 (prompt=login proxy_register) の代理人を ID Token の act として要求する。
// subscriptionID は代理人 (ログイン中のユーザー) の、このサービスのサブスクリプション ID。
// KLON は act を常に必須として扱うため、ClaimOptionFunc は取らない。
func WithActor(subscriptionID string) AuthorizeOptionFunc {
	return WithIDTokenClaim("act", ClaimValue(map[string]string{"sub": subscriptionID}))
}
