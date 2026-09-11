package klon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestClient_PrivateKeyJWT(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var assertions []jwt.Claims
	var paths []string
	server, _ := testOIDCServerWithOptions(t, testOIDCServerOptions{
		checkClientAuth: func(r *http.Request) {
			require.Empty(t, r.Header.Get("Authorization"))
			require.NotContains(t, r.Form, "client_secret")
			require.Equal(t, "test-client", r.Form.Get("client_id"))
			require.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.Form.Get("client_assertion_type"))
			token, err := jwt.ParseSigned(r.Form.Get("client_assertion"), []jose.SignatureAlgorithm{jose.ES256})
			require.NoError(t, err)
			require.Equal(t, "client-key", token.Headers[0].KeyID)
			var claims jwt.Claims
			require.NoError(t, token.Claims(&key.PublicKey, &claims))
			require.NoError(t, claims.Validate(jwt.Expected{Issuer: "test-client", Subject: "test-client", Time: time.Now()}))
			require.Equal(t, int64(60), int64(*claims.Expiry-*claims.IssuedAt))
			require.NotEmpty(t, claims.ID)
			assertions = append(assertions, claims)
			paths = append(paths, r.URL.Path)
		},
	})
	client := NewClient(ClientConfig{Issuer: server.URL, ClientID: "test-client",
		RedirectURI: "http://localhost/callback", ClientPrivateKey: &ClientPrivateKey{Key: key, KeyID: "client-key"}})
	_, session, err := client.CreateAuthorizationURL(t.Context(), AuthorizeOptions{UsePAR: true})
	require.NoError(t, err)
	session.Nonce = "test-nonce"
	tokens, err := client.ExchangeCode(t.Context(), "test-code", session.State, session)
	require.NoError(t, err)
	require.Equal(t, "test-access-token", tokens.AccessToken)
	for range 2 {
		tokens, err = client.RefreshToken(t.Context(), tokens.RefreshToken)
		require.NoError(t, err)
		require.Equal(t, "test-access-token", tokens.AccessToken)
		require.Equal(t, 3600, *tokens.ExpiresIn)
		require.NotNil(t, tokens.IDTokenClaims)
	}
	require.Equal(t, []string{"/par", "/token", "/token", "/token"}, paths)
	ids := map[string]bool{}
	for _, claims := range assertions {
		require.Equal(t, jwt.Audience{server.URL}, claims.Audience)
		require.False(t, ids[claims.ID])
		ids[claims.ID] = true
	}
}

func TestPrivateKeyTokenResponse(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	for _, tc := range []struct {
		name           string
		status         int
		body           string
		wantError      string
		wantOAuthError bool
	}{
		{"success without rotated refresh token", 200, `{"access_token":"access","token_type":"Bearer","expires_in":60,"scope":"openid","authorization_details":[{"type":"urn:klon:resource_access","identifiers":["klon/email_address"],"actions":["read"]}]}`, "", false},
		{"OAuth error", 400, `{"error":"invalid_client","error_description":"invalid assertion"}`, "invalid_client", true},
		{"OAuth error with HTTP 200", 200, `{"error":"invalid_grant"}`, "invalid_grant", true},
		{"HTTP error", 500, `unavailable`, "500", true},
		{"invalid JSON", 200, `{`, "parse token response", false},
		{"missing token", 200, `{}`, "missing access_token", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientHeaders := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				clientHeaders <- r.Header.Get("X-Test-Client")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(server.Close)
			client := NewClient(ClientConfig{Issuer: server.URL, ClientID: "client", ClientPrivateKey: &ClientPrivateKey{Key: key, KeyID: "key"}})
			ctx := oidc.ClientContext(t.Context(), &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				r.Header.Set("X-Test-Client", "custom")
				return http.DefaultTransport.RoundTrip(r)
			})})
			token, err := client.privateKeyTokenRequest(ctx, server.URL, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"original"}})
			require.Len(t, clientHeaders, 1)
			require.Equal(t, "custom", <-clientHeaders)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				if tc.wantOAuthError {
					var retrieveError *oauth2.RetrieveError
					require.ErrorAs(t, err, &retrieveError)
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, "original", token.RefreshToken)
			require.Equal(t, "openid", token.Extra("scope"))
			require.Equal(t, int64(60), token.ExpiresIn)
			require.WithinDuration(t, time.Now().Add(time.Minute), token.Expiry, time.Second)
			details := parseTokenAuthorizationDetails(token.Extra("authorization_details").([]any))
			require.Len(t, details, 1)
		})
	}
}

func TestClient_InvalidPrivateKeyConfig(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrongCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	for _, config := range []ClientConfig{
		{ClientSecret: "secret", ClientPrivateKey: &ClientPrivateKey{Key: key, KeyID: "key"}},
		{ClientPrivateKey: &ClientPrivateKey{KeyID: "key"}},
		{ClientPrivateKey: &ClientPrivateKey{Key: key}},
		{ClientPrivateKey: &ClientPrivateKey{Key: wrongCurve, KeyID: "key"}},
	} {
		client := NewClient(config)
		_, _, err := client.CreateAuthorizationURL(t.Context())
		require.ErrorContains(t, err, "ClientPrivateKey")
		_, err = client.RefreshToken(t.Context(), "refresh")
		require.ErrorContains(t, err, "ClientPrivateKey")
	}
}
