package klon

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClient_Authorize_WithActor(t *testing.T) {
	server, _ := testOIDCServer(t)
	client := NewClient(ClientConfig{Issuer: server.URL, ClientID: "test-client", RedirectURI: "http://localhost/callback"})

	authURL, _, err := client.CreateAuthorizationURL(t.Context(),
		AuthorizeOptions{Prompt: []string{PromptLogin, "proxy_register"}},
		WithActor("actor-subscription-id"),
	)
	require.NoError(t, err)
	require.JSONEq(t, `{"id_token":{"act":{"value":{"sub":"actor-subscription-id"}}}}`, authURL.Query().Get("claims"))
}
