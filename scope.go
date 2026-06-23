package klon

// profile/email などは表示用ラベルではなく、対応する Registry リソースの
// 読み取り権限要求として扱われる。
const (
	// ScopeOpenID は ID トークンの発行を要求するスコープ。
	ScopeOpenID = "openid"
	// ScopeProfile は name/gender/birthdate の読み取りを要求するスコープ。
	ScopeProfile = "profile"
	// ScopeEmail は email/email_verified の読み取りを要求するスコープ。
	ScopeEmail = "email"
	// ScopeOfflineAccess はリフレッシュトークンの発行を要求するスコープ。
	ScopeOfflineAccess = "offline_access"
	// ScopeAddress は住所の読み取りを要求するスコープ。
	ScopeAddress = "address"
	// ScopePhone は phone_number/phone_number_verified の読み取りを要求するスコープ。
	ScopePhone = "phone"
	// ScopePersonalInfo は基本 4 情報の読み取りを要求するスコープ。
	ScopePersonalInfo = "personal_info"
)

// AllScopes は SDK が定義する全スコープの一覧。
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
