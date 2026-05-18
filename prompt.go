package klon

const (
	// 認証・認可画面を表示しない。必要な場合はエラー応答をコールバックする。
	PromptNone = "none"
	// エンドユーザーに再認証を要求する
	PromptLogin = "login"
	// エンドユーザーに明示的な同意を要求する
	PromptConsent = "consent"
)

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
