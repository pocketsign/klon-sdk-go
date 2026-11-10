package klon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClient_Authorize_WithACR(t *testing.T) {
	server, _ := testOIDCServer(t)
	client := NewClient(ClientConfig{Issuer: server.URL, ClientID: "test-client", RedirectURI: "http://localhost/callback"})

	tests := []struct {
		name string
		opt  AuthorizeOptionFunc
		want string
	}{
		{"Essential を渡すと必須で要求する", WithACR([]string{AcrHigh}, Essential()), `{"id_token":{"acr":{"essential":true,"values":["urn:klon:acr:high"]}}}`},
		{"Essential を渡さなければ値だけ送る", WithACR([]string{AcrHigh}), `{"id_token":{"acr":{"values":["urn:klon:acr:high"]}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL, _, err := client.CreateAuthorizationURL(t.Context(), AuthorizeOptions{}, tt.opt)
			require.NoError(t, err)
			require.JSONEq(t, tt.want, authURL.Query().Get("claims"))
		})
	}
}
