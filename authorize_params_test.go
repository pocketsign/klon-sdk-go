package klon

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// authorizeParamsComparedKeys は認可 URL と PAR で値が一致することを確かめるパラメータ
// (state・nonce・PKCE はリクエストごとに変わるので比べない)。
var authorizeParamsComparedKeys = []string{
	"response_type", "redirect_uri", "scope", "code_challenge_method",
	"authorization_details", "acr_values", "prompt", "max_age", "grant_management_action", "claims",
	"ui_locales", "login_hint",
}

func TestClient_Authorize_ExtraParams(t *testing.T) {
	maxAge := 300
	opt := AuthorizeOptions{
		Scopes:    []string{"openid", "profile"},
		AcrValues: []string{AcrHigh},
		Prompt:    []string{PromptLogin},
		MaxAge:    &maxAge,
		AuthorizationDetails: []AuthorizationDetailInput{
			{Identifiers: []string{"klon/test"}, Actions: []ResourceAction{ResourceActionRead}},
		},
		GrantManagementAction: "create",
		ExtraParams: map[string]string{
			"ui_locales": "ja",
			"login_hint": "user@example.com",
		},
	}
	acrClaim := WithIDTokenClaim("acr", Essential(), ClaimValues(AcrHigh))

	t.Run("認可 URL と PAR に同じ値で追加パラメータを載せる", func(t *testing.T) {
		var parForm url.Values
		server, _ := testOIDCServerWithOptions(t, testOIDCServerOptions{
			capturePARForm: func(form url.Values) { parForm = form },
		})
		client := NewClient(ClientConfig{
			Issuer:      server.URL,
			ClientID:    "test-client",
			RedirectURI: "http://localhost/callback",
		})

		authURL, _, err := client.CreateAuthorizationURL(t.Context(), opt, acrClaim)
		require.NoError(t, err)
		parOpt := opt
		parOpt.UsePAR = true
		_, _, err = client.CreateAuthorizationURL(t.Context(), parOpt, acrClaim)
		require.NoError(t, err)
		require.NotNil(t, parForm)

		query := authURL.Query()
		require.Equal(t, "ja", query.Get("ui_locales"))
		require.Equal(t, "user@example.com", query.Get("login_hint"))
		require.JSONEq(t, `{"id_token":{"acr":{"essential":true,"values":["urn:klon:acr:high"]}}}`, query.Get("claims"))
		for _, key := range authorizeParamsComparedKeys {
			require.Equal(t, query[key], parForm[key], key)
		}
	})

	t.Run("追加パラメータを指定しなければ送るパラメータは変わらない", func(t *testing.T) {
		server, _ := testOIDCServer(t)
		client := NewClient(ClientConfig{
			Issuer:      server.URL,
			ClientID:    "test-client",
			RedirectURI: "http://localhost/callback",
		})

		withoutExtra := opt
		withoutExtra.ExtraParams = nil
		authURL, _, err := client.CreateAuthorizationURL(t.Context(), withoutExtra, acrClaim)
		require.NoError(t, err)

		keys := make([]string, 0, len(authURL.Query()))
		for key := range authURL.Query() {
			keys = append(keys, key)
		}
		require.ElementsMatch(t, []string{
			"client_id", "response_type", "redirect_uri", "scope", "state", "nonce",
			"code_challenge", "code_challenge_method",
			"authorization_details", "acr_values", "prompt", "max_age", "grant_management_action", "claims",
		}, keys)
	})

	t.Run("prompt に任意の値を入れても今どおり送る", func(t *testing.T) {
		server, _ := testOIDCServer(t)
		client := NewClient(ClientConfig{
			Issuer:      server.URL,
			ClientID:    "test-client",
			RedirectURI: "http://localhost/callback",
		})

		authURL, _, err := client.CreateAuthorizationURL(t.Context(), AuthorizeOptions{
			Prompt: []string{PromptLogin, "custom_prompt"},
		})
		require.NoError(t, err)
		require.Equal(t, "login custom_prompt", authURL.Query().Get("prompt"))
	})
}

func TestClient_Authorize_Claims(t *testing.T) {
	server, _ := testOIDCServer(t)
	client := NewClient(ClientConfig{
		Issuer:      server.URL,
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
	})

	t.Run("null 要求と value のオブジェクトを JSON にして送る", func(t *testing.T) {
		authURL, _, err := client.CreateAuthorizationURL(t.Context(), AuthorizeOptions{},
			WithIDTokenClaim("auth_time"),
			WithIDTokenClaim("custom", ClaimValue(map[string]any{"sub": "abc"})),
			WithUserinfoClaim("email", Essential()),
		)
		require.NoError(t, err)
		require.JSONEq(t,
			`{"id_token":{"auth_time":null,"custom":{"value":{"sub":"abc"}}},"userinfo":{"email":{"essential":true}}}`,
			authURL.Query().Get("claims"))
	})

	t.Run("SDK の外で定義したオプション関数も AuthorizeOptions の後に適用する", func(t *testing.T) {
		withLocale := AuthorizeOptionFunc(func(o *AuthorizeOptions) {
			o.ExtraParams["ui_locales"] = "ja"
		})
		authURL, _, err := client.CreateAuthorizationURL(t.Context(),
			AuthorizeOptions{ExtraParams: map[string]string{"login_hint": "user@example.com"}},
			withLocale,
		)
		require.NoError(t, err)
		require.Equal(t, "ja", authURL.Query().Get("ui_locales"))
		require.Equal(t, "user@example.com", authURL.Query().Get("login_hint"))
	})

	t.Run("オプション関数を使わなければ ExtraParams の claims をそのまま送る", func(t *testing.T) {
		authURL, _, err := client.CreateAuthorizationURL(t.Context(), AuthorizeOptions{
			ExtraParams: map[string]string{"claims": `{"id_token":{"acr":null}}`},
		})
		require.NoError(t, err)
		require.JSONEq(t, `{"id_token":{"acr":null}}`, authURL.Query().Get("claims"))
	})

	for _, usePAR := range []bool{false, true} {
		t.Run("ExtraParams の claims とマージする", func(t *testing.T) {
			var parForm url.Values
			server, _ := testOIDCServerWithOptions(t, testOIDCServerOptions{
				capturePARForm: func(form url.Values) { parForm = form },
			})
			client := NewClient(ClientConfig{Issuer: server.URL, ClientID: "test-client", RedirectURI: "http://localhost/callback"})
			authURL, _, err := client.CreateAuthorizationURL(t.Context(),
				AuthorizeOptions{UsePAR: usePAR, ExtraParams: map[string]string{"claims": `{"id_token":{"acr":null},"userinfo":{"email":null}}`}},
				WithIDTokenClaim("act", ClaimValue(map[string]string{"sub": "abc"})),
				WithUserinfoClaim("name"),
			)
			require.NoError(t, err)
			got := authURL.Query().Get("claims")
			if usePAR {
				got = parForm.Get("claims")
			}
			require.JSONEq(t, `{"id_token":{"acr":null,"act":{"value":{"sub":"abc"}}},"userinfo":{"email":null,"name":null}}`, got)
		})
	}

	t.Run("同じクレームを ExtraParams とオプション関数の両方で指定したらエラーにする", func(t *testing.T) {
		_, _, err := client.CreateAuthorizationURL(t.Context(),
			AuthorizeOptions{ExtraParams: map[string]string{"claims": `{"id_token":{"acr":null}}`}},
			WithIDTokenClaim("acr", Essential()),
		)
		require.ErrorContains(t, err, `claim "acr" in id_token is specified in both ExtraParams and claim options`)
	})

	t.Run("マージできない ExtraParams の claims はエラーにする", func(t *testing.T) {
		_, _, err := client.CreateAuthorizationURL(t.Context(),
			AuthorizeOptions{ExtraParams: map[string]string{"claims": `not json`}},
			WithIDTokenClaim("acr"),
		)
		require.ErrorContains(t, err, `extra authorize parameter "claims" must be a claims request JSON`)
	})
}

func TestClient_Authorize_ExtraParamsReserved(t *testing.T) {
	// discovery に到達できない issuer にして、通信の前にエラーになることを確かめる
	client := NewClient(ClientConfig{
		Issuer:      "http://127.0.0.1:1",
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
	})

	tests := []struct {
		key     string
		wantErr string
	}{
		{key: "state", wantErr: `"state" is managed by the SDK`},
		{key: "nonce", wantErr: `"nonce" is managed by the SDK`},
		{key: "code_challenge", wantErr: `"code_challenge" is managed by the SDK`},
		{key: "code_challenge_method", wantErr: `"code_challenge_method" is managed by the SDK`},
		{key: "redirect_uri", wantErr: `"redirect_uri" is managed by the SDK`},
		{key: "client_id", wantErr: `"client_id" is managed by the SDK`},
		{key: "response_type", wantErr: `"response_type" is managed by the SDK`},
		{key: "scope", wantErr: `"scope" is managed by the SDK`},
		{key: "request_uri", wantErr: `"request_uri" is managed by the SDK`},
		{key: "dpop_jkt", wantErr: `"dpop_jkt" is managed by the SDK`},
		{key: "client_secret", wantErr: `"client_secret" is managed by the SDK`},
		{key: "client_assertion", wantErr: `"client_assertion" is managed by the SDK`},
		{key: "client_assertion_type", wantErr: `"client_assertion_type" is managed by the SDK`},
		{key: "prompt", wantErr: "use AuthorizeOptions.Prompt instead"},
		{key: "acr_values", wantErr: "use AuthorizeOptions.AcrValues instead"},
		{key: "max_age", wantErr: "use AuthorizeOptions.MaxAge instead"},
		{key: "authorization_details", wantErr: "use AuthorizeOptions.AuthorizationDetails instead"},
		{key: "grant_management_action", wantErr: "use AuthorizeOptions.GrantManagementAction instead"},
		{key: "", wantErr: "must not be empty"},
	}
	for _, tt := range tests {
		for _, usePAR := range []bool{false, true} {
			t.Run(tt.key, func(t *testing.T) {
				_, _, err := client.CreateAuthorizationURL(t.Context(), AuthorizeOptions{
					UsePAR:      usePAR,
					ExtraParams: map[string]string{tt.key: "x"},
				})
				require.ErrorContains(t, err, tt.wantErr)
			})
		}
	}
}
