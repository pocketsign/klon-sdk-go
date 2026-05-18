package klon

import "strings"

const (
	// メールアドレス/外部IdP
	AcrLow = "urn:klon:acr:low"
	// JPKI 利用者証明用電子証明書相当
	AcrHigh = "urn:klon:acr:high"
	// JPKI 署名用電子証明書相当
	AcrVeryHigh = "urn:klon:acr:very_high"
)

var AllAcrValues = []string{
	AcrLow,
	AcrHigh,
	AcrVeryHigh,
}

// BuildAcrValues は ACR 値をスペース区切りの文字列に結合する。重複は除去される。
// オプションの manualValue はスペースで分割して末尾に追加される。
func BuildAcrValues(values []string, manualValue ...string) string {
	var manual string
	if len(manualValue) > 0 {
		manual = manualValue[0]
	}

	manualParts := strings.Fields(manual)

	seen := make(map[string]struct{}, len(values)+len(manualParts))
	result := make([]byte, 0, (len(values)+len(manualParts))*30)

	for _, v := range append(values, manualParts...) {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		if len(result) > 0 {
			result = append(result, ' ')
		}
		result = append(result, v...)
	}

	return string(result)
}
