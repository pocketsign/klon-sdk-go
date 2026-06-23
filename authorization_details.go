package klon

import (
	"encoding/json"
	"fmt"
)

// ResourceAction はリソースに対する操作種別を表す。
type ResourceAction string

const (
	// ResourceActionRead はリソース値の取得を表す。
	ResourceActionRead ResourceAction = "read"
	// ResourceActionWrite はリソース値の更新・削除を表す。
	ResourceActionWrite ResourceAction = "write"
	// ResourceActionInvoke は実行リソースの呼び出しを表す。
	ResourceActionInvoke ResourceAction = "invoke"
)

// AuthorizationDetail は RFC 9396 に基づく単一の認可詳細を表す。
// type は現状 "urn:klon:resource_access" のみで、Registry リソースへの権限要求を表す。
//
// scope と authorization_details を併用した場合、要求は両者の和集合となり、
// 同じ意味の要求は重複しない 1 つに正規化される。
type AuthorizationDetail struct {
	Type        string           `json:"type"`               // 認可詳細の種別。KLON では "urn:klon:resource_access"。
	Identifiers []string         `json:"identifiers"`        // 対象リソースの定義 ID またはエイリアスの配列。
	Actions     []ResourceAction `json:"actions"`            // リソースに対して要求する操作 (read/write/invoke) の一覧。
	Required    *bool            `json:"required,omitempty"` // true なら拒否時に認可フロー自体を継続できない必須要求。
	Prefill     *bool            `json:"prefill,omitempty"`  // true ならリソース値が未登録のとき認可フロー内で値入力・登録を促す。
}

// AuthorizationDetailInput は [BuildAuthorizationDetails] の入力型。
// Type は "urn:klon:resource_access" として自動補完される。
type AuthorizationDetailInput struct {
	Identifiers []string         // 対象リソースの定義 ID またはエイリアスの配列。
	Actions     []ResourceAction // リソースに対して要求する操作 (read/write/invoke) の一覧。
	Required    *bool            // true なら拒否時に認可フロー自体を継続できない必須要求。
	Prefill     *bool            // true ならリソース値が未登録のとき認可フロー内で値入力・登録を促す。
}

// BuildAuthorizationDetails は [AuthorizationDetailInput] のスライスを
// authorization_details パラメータ用の JSON 文字列に変換する。
// 各要素の Type は "urn:klon:resource_access" として自動補完される。
// details が空の場合は "[]" を返す。
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

// ParseAuthorizationDetails は authorization_details の JSON 文字列を
// パースして [AuthorizationDetail] のスライスに変換する。
// 各要素は KLON の認可詳細として妥当か検証され、不正な場合はエラーを返す。
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
