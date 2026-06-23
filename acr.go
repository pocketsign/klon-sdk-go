package klon

import "strings"

// ACR は認証強度を表す 3 段階の値で、上位は下位を包含する
// (AcrVeryHigh は AcrHigh と AcrLow を、AcrHigh は AcrLow を満たす)。
//
// 実効的に要求される ACR は claims.id_token.acr > acr_values >
// クライアント既定値 の優先順位で決定される。再認証の要否は要求リスト中の
// 最弱 ACR を基準に判定され、acr_values の先頭が UI 上の優先候補となる。
const (
	// AcrLow はメール OTP などの低強度認証を表す ACR 値。
	AcrLow = "urn:klon:acr:low"
	// AcrHigh は JPKI 利用者証明用電子証明書相当の認証を表す ACR 値。
	AcrHigh = "urn:klon:acr:high"
	// AcrVeryHigh は JPKI 署名用電子証明書相当の認証を表す ACR 値。
	AcrVeryHigh = "urn:klon:acr:very_high"
)

// AllAcrValues は SDK が定義する全 ACR 値の一覧。
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
