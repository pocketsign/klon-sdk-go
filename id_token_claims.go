package klon

import "encoding/json"

// IDTokenClaims は KLON ID Token のデコード済みクレームを保持する。
// ExchangeCode() / RefreshToken() の戻り値 TokenSet.IDTokenClaims として取得できる。
//
// 常に存在するクレームは値型、scope 依存のオプショナルクレームはポインタ型。
type IDTokenClaims struct {
	// Standard OIDC (always present)
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience Audience `json:"aud"`
	IssuedAt int64    `json:"iat"`
	Expiry   int64    `json:"exp"`
	Nonce    string   `json:"nonce,omitempty"`

	// Auth context (always present)
	AuthTime int64    `json:"auth_time"`
	ACR      string   `json:"acr"`
	AMR      []string `json:"amr"`
	SID      string   `json:"sid,omitempty"`

	// KLON-specific
	UID          string `json:"uid,omitempty"`
	JPKIVerified bool   `json:"jpki_verified"`

	// Profile (scope: "profile")
	Name      *string `json:"name,omitempty"`
	Gender    *string `json:"gender,omitempty"`
	Birthdate *string `json:"birthdate,omitempty"`

	// Email (scope: "email")
	Email         *string `json:"email,omitempty"`
	EmailVerified *bool   `json:"email_verified,omitempty"`

	// Address (scope: "address")
	Address *string `json:"address,omitempty"`

	// Phone (scope: "phone")
	PhoneNumber         *string `json:"phone_number,omitempty"`
	PhoneNumberVerified *bool   `json:"phone_number_verified,omitempty"`
}

// Audience は JWT の aud クレームを表す。
// OIDC 仕様上 string または []string のどちらも取り得るため、両方の JSON 形式を受け付ける。
type Audience []string

func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}

	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	*a = Audience(multi)
	return nil
}

func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}
