package klon

import (
	"encoding/json"
	"fmt"
)

// AuthorizeOptionFunc は [Client.CreateAuthorizationURL] で、AuthorizeOptions を適用した後に呼ばれるオプション関数。
// [WithIDTokenClaim] などが返す。SDK の外でも定義できる。
type AuthorizeOptionFunc func(*AuthorizeOptions)

// ClaimOptionFunc は 1 つのクレームに対する要求 (OIDC Core 5.5.1) を指定するオプション関数。
type ClaimOptionFunc func(*claimRequest)

// Essential はクレームを必須として要求する。
func Essential() ClaimOptionFunc {
	return func(r *claimRequest) { r.Essential = true }
}

// claimsRequest は claims パラメータの JSON。セクション名 (id_token / userinfo) → クレーム名 → 要求 (nil は null)。
type claimsRequest map[string]map[string]*claimRequest

type claimRequest struct {
	Essential bool  `json:"essential,omitempty"`
	Value     any   `json:"value,omitempty"`
	Values    []any `json:"values,omitempty"`
}

// ClaimValue はクレームに特定の値を要求する ("value")。
func ClaimValue(value any) ClaimOptionFunc {
	return func(r *claimRequest) { r.Value = value }
}

// ClaimValues はクレームに値の候補を要求する ("values")。
func ClaimValues(values ...any) ClaimOptionFunc {
	return func(r *claimRequest) { r.Values = values }
}

// WithIDTokenClaim は claims パラメータ (OIDC Core 5.5) で、ID Token に含めるクレームを要求する。
// opts を渡さなければ、そのクレームを通常どおり要求する (JSON の null)。
// ExtraParams にも claims があればマージして送る。同じクレームを両方で指定したらエラーになる。
func WithIDTokenClaim(name string, opts ...ClaimOptionFunc) AuthorizeOptionFunc {
	return withClaim("id_token", name, opts)
}

// WithUserinfoClaim は claims パラメータ (OIDC Core 5.5) で、UserInfo の応答に含めるクレームを要求する。
// それ以外は [WithIDTokenClaim] と同じ。
func WithUserinfoClaim(name string, opts ...ClaimOptionFunc) AuthorizeOptionFunc {
	return withClaim("userinfo", name, opts)
}

func withClaim(section, name string, opts []ClaimOptionFunc) AuthorizeOptionFunc {
	var req *claimRequest
	if len(opts) > 0 {
		req = &claimRequest{}
		for _, o := range opts {
			o(req)
		}
	}
	return func(dst *AuthorizeOptions) {
		if dst.claims == nil {
			dst.claims = claimsRequest{}
		}
		if dst.claims[section] == nil {
			dst.claims[section] = map[string]*claimRequest{}
		}
		dst.claims[section][name] = req
	}
}

// buildClaims はオプション関数で指定したクレームを、ExtraParams の claims (無ければ空文字) にマージした JSON を返す。
// オプション関数で何も指定していなければ extra をそのまま返す。
func buildClaims(claims claimsRequest, extra string) (string, error) {
	if len(claims) == 0 {
		return extra, nil
	}
	merged := map[string]map[string]json.RawMessage{}
	if extra != "" {
		if err := json.Unmarshal([]byte(extra), &merged); err != nil {
			return "", fmt.Errorf(`extra authorize parameter "claims" must be a claims request JSON to merge with claim options: %w`, err)
		}
	}
	for section, reqs := range claims {
		if merged[section] == nil {
			merged[section] = map[string]json.RawMessage{}
		}
		for name, req := range reqs {
			if _, ok := merged[section][name]; ok {
				return "", fmt.Errorf("claim %q in %s is specified in both ExtraParams and claim options", name, section)
			}
			raw, err := json.Marshal(req)
			if err != nil {
				return "", fmt.Errorf("failed to build claims: %w", err)
			}
			merged[section][name] = raw
		}
	}
	out, err := json.Marshal(merged)
	if err != nil {
		return "", fmt.Errorf("failed to build claims: %w", err)
	}
	return string(out), nil
}
