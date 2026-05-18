// Package klon は KLON IdP 向けの OIDC クライアント SDK を提供する。
//
// go-oidc と x/oauth2 をベースに、KLON 固有のパラメータ
// (ACR values, authorization details (RFC 9396), リソーススコープ) をラップする。
package klon

import (
	"encoding/json"
	"fmt"
)

type ResourceAction string

const (
	ResourceActionRead   ResourceAction = "read"
	ResourceActionWrite  ResourceAction = "write"
	ResourceActionInvoke ResourceAction = "invoke"
)

// AuthorizationDetail は RFC 9396 に基づく単一の認可詳細を表す。
type AuthorizationDetail struct {
	Type        string           `json:"type"`
	Identifiers []string         `json:"identifiers"`
	Actions     []ResourceAction `json:"actions"`
	Required    *bool            `json:"required,omitempty"`
	Prefill     *bool            `json:"prefill,omitempty"`
}

// AuthorizationDetailInput は BuildAuthorizationDetails の入力型。
// Type は "urn:klon:resource_access" として自動補完される。
type AuthorizationDetailInput struct {
	Identifiers []string
	Actions     []ResourceAction
	Required    *bool
	Prefill     *bool
}

func BuildAuthorizationDetails(details []AuthorizationDetailInput) (string, error) {
	if len(details) == 0 {
		return "[]", nil
	}

	result := make([]AuthorizationDetail, len(details))
	for i, d := range details {
		result[i] = AuthorizationDetail{
			Type:        "urn:klon:resource_access",
			Identifiers: d.Identifiers,
			Actions:     d.Actions,
			Required:    d.Required,
			Prefill:     d.Prefill,
		}
	}

	b, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to marshal authorization_details: %w", err)
	}
	return string(b), nil
}

func isValidResourceAction(s string) bool {
	return s == string(ResourceActionRead) || s == string(ResourceActionWrite) || s == string(ResourceActionInvoke)
}

func ParseAuthorizationDetails(jsonStr string) ([]AuthorizationDetail, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		var single json.RawMessage
		if json.Unmarshal([]byte(jsonStr), &single) == nil && len(jsonStr) > 0 && jsonStr[0] != '[' {
			return nil, fmt.Errorf("authorization_details must be an array")
		}
		return nil, fmt.Errorf("failed to parse authorization_details: %w", err)
	}

	result := make([]AuthorizationDetail, 0, len(raw))
	for i, r := range raw {
		var m map[string]any
		if err := json.Unmarshal(r, &m); err != nil {
			return nil, fmt.Errorf("authorization_details[%d]: invalid format", i)
		}

		if err := validateAuthorizationDetail(m); err != nil {
			return nil, fmt.Errorf("authorization_details[%d]: %w", i, err)
		}

		var detail AuthorizationDetail
		if err := json.Unmarshal(r, &detail); err != nil {
			return nil, fmt.Errorf("authorization_details[%d]: invalid format", i)
		}
		result = append(result, detail)
	}

	return result, nil
}

func validateAuthorizationDetail(m map[string]any) error {
	if m["type"] != "urn:klon:resource_access" {
		return fmt.Errorf("invalid type %q", m["type"])
	}

	identifiers, ok := m["identifiers"].([]any)
	if !ok {
		return fmt.Errorf("identifiers must be an array")
	}
	for _, id := range identifiers {
		if _, ok := id.(string); !ok {
			return fmt.Errorf("identifiers must contain strings")
		}
	}

	actions, ok := m["actions"].([]any)
	if !ok {
		return fmt.Errorf("actions must be an array")
	}
	for _, a := range actions {
		s, ok := a.(string)
		if !ok || !isValidResourceAction(s) {
			return fmt.Errorf("invalid action %q", a)
		}
	}

	if req, exists := m["required"]; exists {
		if _, ok := req.(bool); !ok {
			return fmt.Errorf("required must be a boolean")
		}
	}

	if pf, exists := m["prefill"]; exists {
		if _, ok := pf.(bool); !ok {
			return fmt.Errorf("prefill must be a boolean")
		}
	}

	return nil
}
