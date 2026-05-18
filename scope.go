package klon

const (
	// OpenID Connect
	ScopeOpenID = "openid"
	// 氏名/生年月日/性別
	ScopeProfile = "profile"
	// メールアドレス
	ScopeEmail = "email"
	// リフレッシュトークン
	ScopeOfflineAccess = "offline_access"
	// 住所
	ScopeAddress = "address"
	// 電話番号
	ScopePhone = "phone"
	// 基本4情報
	ScopePersonalInfo = "personal_info"
)

var AllScopes = []string{
	ScopeOpenID,
	ScopeProfile,
	ScopeEmail,
	ScopeOfflineAccess,
	ScopeAddress,
	ScopePhone,
	ScopePersonalInfo,
}

// BuildScope はスコープ値をスペース区切りの文字列に結合する。重複は除去される。
func BuildScope(scopes ...string) string {
	seen := make(map[string]struct{}, len(scopes))
	result := make([]byte, 0, len(scopes)*10)
	for _, s := range scopes {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		if len(result) > 0 {
			result = append(result, ' ')
		}
		result = append(result, s...)
	}
	return string(result)
}
