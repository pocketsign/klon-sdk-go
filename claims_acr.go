package klon

// WithACR は claims パラメータで、ID Token の acr を要求する。
// 必須にするときは Essential を渡す (KLON は essential のときだけ、その ACR での認証を求める)。
// 希望するだけなら AuthorizeOptions.AcrValues を使う。
func WithACR(acrs []string, opts ...ClaimOptionFunc) AuthorizeOptionFunc {
	values := make([]any, len(acrs))
	for i, acr := range acrs {
		values[i] = acr
	}
	return WithIDTokenClaim("acr", append([]ClaimOptionFunc{ClaimValues(values...)}, opts...)...)
}
