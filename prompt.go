package klon

// KLON がサポートする prompt は none/login/consent のみ。
const (
	// PromptNone は認証・認可画面を表示しない。必要な場合はエラー応答をコールバックする。
	PromptNone = "none"
	// PromptLogin はエンドユーザーに再認証を要求する。
	// 必ずしもログアウトを意味せず、既存セッションを維持したまま再認証のみ行う。
	PromptLogin = "login"
	// PromptConsent はエンドユーザーに明示的な同意を要求する。
	// 同意が再利用可能な場合でも同意画面を表示する。
	PromptConsent = "consent"
)

// AllPrompts は SDK が定義する全 prompt 値の一覧。
var AllPrompts = []string{
	PromptNone,
	PromptLogin,
	PromptConsent,
}

// BuildPrompt は prompt 値をスペース区切りの文字列に結合する。重複は除去される。
// none は他の prompt と併用できない。login と consent は併用可能。
func BuildPrompt(prompts ...string) string {
	seen := make(map[string]struct{}, len(prompts))
	result := make([]byte, 0, len(prompts)*10)
	for _, p := range prompts {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		if len(result) > 0 {
			result = append(result, ' ')
		}
		result = append(result, p...)
	}
	return string(result)
}
