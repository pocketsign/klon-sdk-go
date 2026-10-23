package klon

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// sdkManagedAuthorizeParams は SDK が値を決めるため、ExtraParams で指定できないパラメータ。
var sdkManagedAuthorizeParams = map[string]struct{}{
	"client_id":             {},
	"response_type":         {},
	"redirect_uri":          {},
	"scope":                 {},
	"state":                 {},
	"nonce":                 {},
	"code_challenge":        {},
	"code_challenge_method": {},
	"request_uri":           {},
	"dpop_jkt":              {},
	"client_secret":         {},
	"client_assertion":      {},
	"client_assertion_type": {},
}

// typedAuthorizeParams は AuthorizeOptions の型付きフィールドで指定するため、ExtraParams で指定できないパラメータ。
var typedAuthorizeParams = map[string]string{
	"authorization_details":   "AuthorizationDetails",
	"acr_values":              "AcrValues",
	"prompt":                  "Prompt",
	"max_age":                 "MaxAge",
	"grant_management_action": "GrantManagementAction",
}

// buildAuthorizeRequestParams は認可 URL と PAR の両方に載せる、AuthorizeOptions 由来のパラメータを組み立てる。
// state・nonce・PKCE・client_id・redirect_uri・scope など SDK が値を決めるパラメータは含まない。
func buildAuthorizeRequestParams(opt AuthorizeOptions) (url.Values, error) {
	if err := validateExtraParams(opt.ExtraParams); err != nil {
		return nil, err
	}

	params := url.Values{}
	if len(opt.AuthorizationDetails) > 0 {
		adJSON, err := BuildAuthorizationDetails(opt.AuthorizationDetails)
		if err != nil {
			return nil, fmt.Errorf("failed to build authorization_details: %w", err)
		}
		params.Set("authorization_details", adJSON)
	}
	if acrValues := strings.Join(opt.AcrValues, " "); acrValues != "" {
		params.Set("acr_values", acrValues)
	}
	if prompt := BuildPrompt(opt.Prompt...); prompt != "" {
		params.Set("prompt", prompt)
	}
	if opt.MaxAge != nil {
		params.Set("max_age", strconv.Itoa(*opt.MaxAge))
	}
	if opt.GrantManagementAction != "" {
		params.Set("grant_management_action", string(opt.GrantManagementAction))
	}
	for key, value := range opt.ExtraParams {
		params.Set(key, value)
	}
	return params, nil
}

func validateExtraParams(extra map[string]string) error {
	for key := range extra {
		if key == "" {
			return fmt.Errorf("extra authorize parameter name must not be empty")
		}
		if _, ok := sdkManagedAuthorizeParams[key]; ok {
			return fmt.Errorf("extra authorize parameter %q is managed by the SDK and cannot be specified", key)
		}
		if field, ok := typedAuthorizeParams[key]; ok {
			return fmt.Errorf("extra authorize parameter %q cannot be specified; use AuthorizeOptions.%s instead", key, field)
		}
	}
	return nil
}
