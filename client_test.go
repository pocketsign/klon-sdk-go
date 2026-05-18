package klon

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
)

// testOIDCServer creates a mock OIDC server with discovery, JWKS, token, and PAR endpoints.
func testOIDCServer(t *testing.T) (*httptest.Server, crypto.Signer) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mux := http.NewServeMux()
	var serverURL string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                serverURL,
			"authorization_endpoint":                serverURL + "/authorize",
			"token_endpoint":                        serverURL + "/token",
			"pushed_authorization_request_endpoint": serverURL + "/par",
			"jwks_uri":                              serverURL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"subject_types_supported":               []string{"pairwise"},
			"response_types_supported":              []string{"code"},
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{
			Key:       &privateKey.PublicKey,
			KeyID:     "test-key",
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()

		nonce := r.Form.Get("nonce")

		signer, err := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       privateKey,
		}, (&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), "test-key"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		now := time.Now()
		claims := jwt.Claims{
			Issuer:    serverURL,
			Subject:   "test-user",
			Audience:  jwt.Audience{"test-client"},
			IssuedAt:  jwt.NewNumericDate(now),
			Expiry:    jwt.NewNumericDate(now.Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(now),
		}

		type extraClaims struct {
			Nonce        string   `json:"nonce,omitempty"`
			AuthTime     int64    `json:"auth_time"`
			ACR          string   `json:"acr"`
			AMR          []string `json:"amr"`
			JPKIVerified bool     `json:"jpki_verified"`
		}
		extra := extraClaims{
			Nonce:        nonce,
			AuthTime:     now.Unix(),
			ACR:          "urn:klon:acr:high",
			AMR:          []string{"mpa"},
			JPKIVerified: true,
		}
		if nonce == "" {
			extra.Nonce = "test-nonce"
		}

		idToken, err := jwt.Signed(signer).Claims(claims).Claims(extra).Serialize()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resp := map[string]any{
			"access_token":  "test-access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "test-refresh-token",
			"id_token":      idToken,
			"scope":         "openid profile",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/par", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"request_uri": "urn:example:par:request_uri:12345",
			"expires_in":  60,
		})
	})

	server := httptest.NewServer(mux)
	serverURL = server.URL
	t.Cleanup(server.Close)

	return server, privateKey
}

func TestClient_Authorize(t *testing.T) {
	server, _ := testOIDCServer(t)

	client := NewClient(ClientConfig{
		Issuer:      server.URL,
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
	})

	t.Run("generates authorization URL with PKCE", func(t *testing.T) {
		authURL, session, err := client.CreateAuthorizationURL(t.Context())
		require.NoError(t, err)
		require.NotNil(t, authURL)
		require.NotNil(t, session)

		q := authURL.Query()
		require.Equal(t, "test-client", q.Get("client_id"))
		require.Equal(t, "code", q.Get("response_type"))
		require.Equal(t, "http://localhost/callback", q.Get("redirect_uri"))
		require.Equal(t, "S256", q.Get("code_challenge_method"))
		require.NotEmpty(t, q.Get("code_challenge"))
		require.NotEmpty(t, q.Get("state"))
		require.NotEmpty(t, q.Get("nonce"))
		require.Contains(t, q.Get("scope"), "openid")

		require.NotEmpty(t, session.State)
		require.NotEmpty(t, session.Nonce)
		require.NotEmpty(t, session.CodeVerifier)
		require.Equal(t, "http://localhost/callback", session.RedirectURI)
	})

	t.Run("includes optional parameters", func(t *testing.T) {
		maxAge := 300
		authURL, _, err := client.CreateAuthorizationURL(t.Context(), AuthorizeOptions{
			Scopes:    []string{"openid", "profile", "email"},
			AcrValues: []string{AcrHigh},
			Prompt:    []string{"consent"},
			MaxAge:    &maxAge,
			AuthorizationDetails: []AuthorizationDetailInput{
				{Identifiers: []string{"klon/test"}, Actions: []ResourceAction{ResourceActionRead}},
			},
			GrantManagementAction: "create",
		})
		require.NoError(t, err)

		q := authURL.Query()
		require.Contains(t, q.Get("scope"), "profile")
		require.Equal(t, AcrHigh, q.Get("acr_values"))
		require.Equal(t, "consent", q.Get("prompt"))
		require.Equal(t, "300", q.Get("max_age"))
		require.NotEmpty(t, q.Get("authorization_details"))
		require.Equal(t, "create", q.Get("grant_management_action"))
	})

	t.Run("PAR generates URL with request_uri", func(t *testing.T) {
		authURL, _, err := client.CreateAuthorizationURL(t.Context(), AuthorizeOptions{
			UsePAR: true,
		})
		require.NoError(t, err)

		q := authURL.Query()
		require.Equal(t, "test-client", q.Get("client_id"))
		require.Equal(t, "urn:example:par:request_uri:12345", q.Get("request_uri"))
		require.Empty(t, q.Get("code_challenge"))
	})
}

func TestClient_ExchangeCode(t *testing.T) {
	server, _ := testOIDCServer(t)

	client := NewClient(ClientConfig{
		Issuer:       server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURI:  "http://localhost/callback",
	})

	t.Run("exchanges code for tokens", func(t *testing.T) {
		_, session, err := client.CreateAuthorizationURL(t.Context())
		require.NoError(t, err)

		session.Nonce = "test-nonce"

		tokenSet, err := client.ExchangeCode(t.Context(), "test-code", session.State, session)
		require.NoError(t, err)
		require.Equal(t, "test-access-token", tokenSet.AccessToken)
		require.Equal(t, "Bearer", tokenSet.TokenType)
		require.Equal(t, "test-refresh-token", tokenSet.RefreshToken)
		require.NotEmpty(t, tokenSet.IDToken)

		require.NotNil(t, tokenSet.IDTokenClaims)
		require.Equal(t, server.URL, tokenSet.IDTokenClaims.Issuer)
		require.Equal(t, "test-user", tokenSet.IDTokenClaims.Subject)
		require.Equal(t, Audience{"test-client"}, tokenSet.IDTokenClaims.Audience)
		require.Equal(t, "test-nonce", tokenSet.IDTokenClaims.Nonce)
		require.Equal(t, "urn:klon:acr:high", tokenSet.IDTokenClaims.ACR)
		require.Equal(t, []string{"mpa"}, tokenSet.IDTokenClaims.AMR)
		require.True(t, tokenSet.IDTokenClaims.JPKIVerified)
		require.NotZero(t, tokenSet.IDTokenClaims.AuthTime)
		require.NotZero(t, tokenSet.IDTokenClaims.IssuedAt)
		require.NotZero(t, tokenSet.IDTokenClaims.Expiry)
	})

	t.Run("state mismatch returns error", func(t *testing.T) {
		_, session, err := client.CreateAuthorizationURL(t.Context())
		require.NoError(t, err)

		_, err = client.ExchangeCode(t.Context(), "test-code", "wrong-state", session)
		require.ErrorContains(t, err, "state mismatch")
	})

	t.Run("nonce mismatch returns error", func(t *testing.T) {
		_, session, err := client.CreateAuthorizationURL(t.Context())
		require.NoError(t, err)

		session.Nonce = "wrong-nonce"

		_, err = client.ExchangeCode(t.Context(), "test-code", session.State, session)
		require.ErrorContains(t, err, "nonce mismatch")
	})
}

func TestClient_Refresh(t *testing.T) {
	server, _ := testOIDCServer(t)

	client := NewClient(ClientConfig{
		Issuer:       server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURI:  "http://localhost/callback",
	})

	t.Run("refreshes token", func(t *testing.T) {
		tokenSet, err := client.RefreshToken(t.Context(), "test-refresh-token")
		require.NoError(t, err)
		require.Equal(t, "test-access-token", tokenSet.AccessToken)
		require.Equal(t, "Bearer", tokenSet.TokenType)
		require.NotEmpty(t, tokenSet.IDToken)
		require.NotNil(t, tokenSet.IDTokenClaims)
		require.Equal(t, "test-user", tokenSet.IDTokenClaims.Subject)
		require.Equal(t, "urn:klon:acr:high", tokenSet.IDTokenClaims.ACR)
		require.True(t, tokenSet.IDTokenClaims.JPKIVerified)
	})
}

func TestClient_DiscoveryCaching(t *testing.T) {
	callCount := 0
	mux := http.NewServeMux()
	var serverURL string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                serverURL,
			"authorization_endpoint":                serverURL + "/authorize",
			"token_endpoint":                        serverURL + "/token",
			"jwks_uri":                              serverURL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"subject_types_supported":               []string{"pairwise"},
			"response_types_supported":              []string{"code"},
		})
	})

	server := httptest.NewServer(mux)
	serverURL = server.URL
	defer server.Close()

	client := NewClient(ClientConfig{
		Issuer:      server.URL,
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
	})

	ctx := context.Background()
	_, _, err := client.CreateAuthorizationURL(ctx)
	require.NoError(t, err)
	_, _, err = client.CreateAuthorizationURL(ctx)
	require.NoError(t, err)

	require.Equal(t, 1, callCount, "discovery should be called only once")
}

func TestClient_PARWithoutEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	var serverURL string

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                serverURL,
			"authorization_endpoint":                serverURL + "/authorize",
			"token_endpoint":                        serverURL + "/token",
			"jwks_uri":                              serverURL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"subject_types_supported":               []string{"pairwise"},
			"response_types_supported":              []string{"code"},
		})
	})

	server := httptest.NewServer(mux)
	serverURL = server.URL
	defer server.Close()

	client := NewClient(ClientConfig{
		Issuer:      server.URL,
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
	})

	_, _, err := client.CreateAuthorizationURL(context.Background(), AuthorizeOptions{
		UsePAR: true,
	})
	require.ErrorContains(t, err, "pushed_authorization_request_endpoint")
}

func TestNewClient(t *testing.T) {
	config := ClientConfig{
		Issuer:       "https://example.com",
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		RedirectURI:  "http://localhost/callback",
	}

	client := NewClient(config)
	require.NotNil(t, client)
	require.Equal(t, config.Issuer, client.config.Issuer)
	require.Equal(t, config.ClientID, client.config.ClientID)
}

func TestParseTokenAuthorizationDetails(t *testing.T) {
	boolTrue := true
	raw := []any{
		map[string]any{
			"type":        "urn:klon:resource_access",
			"identifiers": []any{"klon/merged_full_name"},
			"actions":     []any{"read"},
			"required":    true,
		},
		map[string]any{
			"type": "unknown_type",
		},
	}

	result := parseTokenAuthorizationDetails(raw)
	require.Len(t, result, 1)
	require.Equal(t, "urn:klon:resource_access", result[0].Type)
	require.Equal(t, &boolTrue, result[0].Required)
}

func TestAudience_UnmarshalJSON(t *testing.T) {
	t.Run("single string", func(t *testing.T) {
		var a Audience
		err := json.Unmarshal([]byte(`"client-id"`), &a)
		require.NoError(t, err)
		require.Equal(t, Audience{"client-id"}, a)
	})

	t.Run("array", func(t *testing.T) {
		var a Audience
		err := json.Unmarshal([]byte(`["client-1","client-2"]`), &a)
		require.NoError(t, err)
		require.Equal(t, Audience{"client-1", "client-2"}, a)
	})
}

func TestDecodeIDTokenPayload(t *testing.T) {
	t.Run("valid JWT", func(t *testing.T) {
		var claims IDTokenClaims
		// Minimal JWT with base64url-encoded payload: {"sub":"test","jpki_verified":true}
		payload := "eyJzdWIiOiJ0ZXN0IiwianBraV92ZXJpZmllZCI6dHJ1ZX0"
		rawJWT := "eyJhbGciOiJSUzI1NiJ9." + payload + ".signature"
		err := decodeIDTokenPayload(rawJWT, &claims)
		require.NoError(t, err)
		require.Equal(t, "test", claims.Subject)
		require.True(t, claims.JPKIVerified)
	})

	t.Run("invalid format", func(t *testing.T) {
		var claims IDTokenClaims
		err := decodeIDTokenPayload("not-a-jwt", &claims)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid JWT format")
	})
}

func TestComputeS256Challenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := computeS256Challenge(verifier)
	require.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge)
}

func TestBuildScope_Integration(t *testing.T) {
	server, _ := testOIDCServer(t)

	client := NewClient(ClientConfig{
		Issuer:      server.URL,
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
	})

	authURL, _, err := client.CreateAuthorizationURL(t.Context(), AuthorizeOptions{
		Scopes: []string{ScopeOpenID, ScopeProfile, ScopeEmail},
	})
	require.NoError(t, err)

	q := authURL.Query()
	scopeParam := q.Get("scope")
	require.Contains(t, scopeParam, "openid")
	require.Contains(t, scopeParam, "profile")
	require.Contains(t, scopeParam, "email")
}

func TestBuildAuthorizationDetails_Integration(t *testing.T) {
	server, _ := testOIDCServer(t)

	client := NewClient(ClientConfig{
		Issuer:      server.URL,
		ClientID:    "test-client",
		RedirectURI: "http://localhost/callback",
	})

	boolTrue := true
	authURL, _, err := client.CreateAuthorizationURL(t.Context(), AuthorizeOptions{
		AuthorizationDetails: []AuthorizationDetailInput{
			{Identifiers: []string{ResourceMergedFullName}, Actions: []ResourceAction{ResourceActionRead}, Required: &boolTrue},
		},
	})
	require.NoError(t, err)

	q := authURL.Query()
	adParam := q.Get("authorization_details")
	require.NotEmpty(t, adParam)

	parsed, err := ParseAuthorizationDetails(adParam)
	require.NoError(t, err)
	require.Len(t, parsed, 1)

	unescaped, err := url.QueryUnescape(adParam)
	_ = unescaped
	require.NoError(t, err)
}
