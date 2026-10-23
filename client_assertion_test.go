package klon

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// quotaError imitates a provider-specific error such as *googleapi.Error.
type quotaError struct{ Code int }

func (e *quotaError) Error() string { return "quota exceeded" }

func newP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func failingSigner(key *ecdsa.PrivateKey) externalTestSigner {
	return externalTestSigner{publicKey: key.Public(), sign: func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
		return nil, &quotaError{Code: 429}
	}}
}

func parseClientAssertion(t *testing.T, assertion string, key *ecdsa.PrivateKey) (jose.Header, jwt.Claims) {
	t.Helper()
	token, err := jwt.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)
	var claims jwt.Claims
	require.NoError(t, token.Claims(&key.PublicKey, &claims))
	return token.Headers[0], claims
}

func TestClient_ClientAssertion(t *testing.T) {
	key := newP256Key(t)

	t.Run("claims と header", func(t *testing.T) {
		server := newAuthTestServer(t, authTestServerOptions{})
		client := NewClient(ClientConfig{Issuer: server.Issuer, ClientID: "client",
			ClientPrivateKey: &ClientPrivateKey{Key: key, KeyID: "key-1"}})
		assertion, err := client.ClientAssertion(t.Context())
		require.NoError(t, err)

		header, claims := parseClientAssertion(t, assertion, key)
		require.Equal(t, string(jose.ES256), header.Algorithm)
		require.Equal(t, "key-1", header.KeyID)
		require.Equal(t, "client", claims.Issuer)
		require.Equal(t, "client", claims.Subject)
		require.Equal(t, jwt.Audience{server.Issuer}, claims.Audience)
		require.WithinDuration(t, time.Now(), claims.IssuedAt.Time(), 2*time.Second)
		require.Equal(t, time.Minute, claims.Expiry.Time().Sub(claims.IssuedAt.Time()))
		require.NotEmpty(t, claims.ID)

		another, err := client.ClientAssertion(t.Context())
		require.NoError(t, err)
		_, anotherClaims := parseClientAssertion(t, another, key)
		require.NotEqual(t, claims.ID, anotherClaims.ID)
		require.Equal(t, 1, server.discoveries())
	})

	t.Run("aud は Issuer Identifier そのもの", func(t *testing.T) {
		server := newAuthTestServer(t, authTestServerOptions{issuerPath: "/tenants/a"})
		client := NewClient(ClientConfig{Issuer: server.Issuer, ClientID: "client",
			ClientPrivateKey: &ClientPrivateKey{Key: key, KeyID: "key"}})
		assertion, err := client.ClientAssertion(t.Context())
		require.NoError(t, err)
		_, claims := parseClientAssertion(t, assertion, key)
		require.Equal(t, jwt.Audience{server.URL + "/tenants/a"}, claims.Audience)
	})

	t.Run("Issuer が discovery の issuer と一致しなければ署名しない", func(t *testing.T) {
		server := newAuthTestServer(t, authTestServerOptions{})
		signCalls := 0
		client := NewClient(ClientConfig{Issuer: server.Issuer + "/", ClientID: "client",
			ClientPrivateKey: &ClientPrivateKey{KeyID: "key", Key: externalTestSigner{publicKey: key.Public(),
				sign: func(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
					signCalls++
					return key.Sign(random, digest, opts)
				}}}})
		_, err := client.ClientAssertion(t.Context())
		require.ErrorContains(t, err, "did not match")
		require.Zero(t, signCalls)
	})

	t.Run("ClientPrivateKey 未設定", func(t *testing.T) {
		client := NewClient(ClientConfig{Issuer: "https://id.example.com", ClientID: "client", ClientSecret: "secret"})
		_, err := client.ClientAssertion(t.Context())
		require.ErrorContains(t, err, "requires ClientPrivateKey")
	})

	t.Run("ctx キャンセル済みなら署名しない", func(t *testing.T) {
		server := newAuthTestServer(t, authTestServerOptions{})
		signCalls := 0
		client := NewClient(ClientConfig{Issuer: server.Issuer, ClientID: "client",
			ClientPrivateKey: &ClientPrivateKey{KeyID: "key", Key: externalTestSigner{publicKey: key.Public(),
				sign: func(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
					signCalls++
					return key.Sign(random, digest, opts)
				}}}})
		// discovery をキャッシュ済みにして、キャンセル判定が署名前に効くことを確認する。
		_, err := client.ClientAssertion(t.Context())
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err = client.ClientAssertion(ctx)
		require.ErrorIs(t, err, context.Canceled)
		require.Equal(t, 1, signCalls)
	})

	t.Run("署名器のエラーを errors.As で取り出せる", func(t *testing.T) {
		server := newAuthTestServer(t, authTestServerOptions{})
		client := NewClient(ClientConfig{Issuer: server.Issuer, ClientID: "client",
			ClientPrivateKey: &ClientPrivateKey{Key: failingSigner(key), KeyID: "key"}})
		_, err := client.ClientAssertion(t.Context())
		var qe *quotaError
		require.ErrorAs(t, err, &qe)
		require.Equal(t, 429, qe.Code)
	})
}

type authTestResponse struct {
	status int
	body   string
}

type authTestServerOptions struct {
	issuerPath        string // issuer に付ける path (例: "/tenants/a")
	revoke            authTestResponse
	withoutRevocation bool
}

// authTestServer serves discovery plus a revocation endpoint with a fixed response,
// and records the received forms so that tests can assert on them after the call.
type authTestServer struct {
	*httptest.Server
	Issuer         string
	mu             sync.Mutex
	forms          []url.Values
	discoveryCalls int
}

func (s *authTestServer) received() []url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.forms
}

func (s *authTestServer) discoveries() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.discoveryCalls
}

func newAuthTestServer(t *testing.T, opts authTestServerOptions) *authTestServer {
	t.Helper()
	s := &authTestServer{}
	mux := http.NewServeMux()
	var serverURL string
	mux.HandleFunc(opts.issuerPath+"/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.discoveryCalls++
		s.mu.Unlock()
		metadata := map[string]any{
			"issuer":                                serverURL + opts.issuerPath,
			"authorization_endpoint":                serverURL + "/authorize",
			"token_endpoint":                        serverURL + "/token",
			"jwks_uri":                              serverURL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		if !opts.withoutRevocation {
			metadata["revocation_endpoint"] = serverURL + "/revoke"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		s.mu.Lock()
		s.forms = append(s.forms, r.PostForm)
		s.mu.Unlock()
		status := opts.revoke.status
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(opts.revoke.body))
	})
	s.Server = httptest.NewServer(mux)
	serverURL = s.URL
	s.Issuer = serverURL + opts.issuerPath
	t.Cleanup(s.Close)
	return s
}

func requirePrivateKeyJWT(t *testing.T, form url.Values, key *ecdsa.PrivateKey, audience string) {
	t.Helper()
	require.Equal(t, "client", form.Get("client_id"))
	require.NotContains(t, form, "client_secret")
	require.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", form.Get("client_assertion_type"))
	_, claims := parseClientAssertion(t, form.Get("client_assertion"), key)
	require.NoError(t, claims.Validate(jwt.Expected{Issuer: "client", Subject: "client",
		AnyAudience: jwt.Audience{audience}, Time: time.Now()}))
}

func TestClient_RevokeToken(t *testing.T) {
	key := newP256Key(t)

	t.Run("private_key_jwt", func(t *testing.T) {
		server := newAuthTestServer(t, authTestServerOptions{})
		client := NewClient(ClientConfig{Issuer: server.URL, ClientID: "client",
			ClientPrivateKey: &ClientPrivateKey{Key: key, KeyID: "key"}})
		require.NoError(t, client.RevokeToken(t.Context(), "refresh-token", "refresh_token"))

		forms := server.received()
		require.Len(t, forms, 1)
		require.Equal(t, "refresh-token", forms[0].Get("token"))
		require.Equal(t, "refresh_token", forms[0].Get("token_type_hint"))
		requirePrivateKeyJWT(t, forms[0], key, server.URL)
	})

	t.Run("client_secret_post / hint 省略", func(t *testing.T) {
		server := newAuthTestServer(t, authTestServerOptions{})
		client := NewClient(ClientConfig{Issuer: server.URL, ClientID: "client", ClientSecret: "secret"})
		require.NoError(t, client.RevokeToken(t.Context(), "access-token", ""))

		forms := server.received()
		require.Len(t, forms, 1)
		require.Equal(t, "access-token", forms[0].Get("token"))
		require.NotContains(t, forms[0], "token_type_hint")
		require.Equal(t, "secret", forms[0].Get("client_secret"))
	})

	t.Run("エラー応答", func(t *testing.T) {
		for _, tc := range []struct {
			name, body, wantCode string
			status               int
		}{
			{"OAuth エラー", `{"error":"invalid_client","error_description":"invalid client assertion"}`, "invalid_client", http.StatusUnauthorized},
			{"非 JSON", `unavailable`, "", http.StatusServiceUnavailable},
		} {
			t.Run(tc.name, func(t *testing.T) {
				server := newAuthTestServer(t, authTestServerOptions{revoke: authTestResponse{status: tc.status, body: tc.body}})
				client := NewClient(ClientConfig{Issuer: server.URL, ClientID: "client",
					ClientPrivateKey: &ClientPrivateKey{Key: key, KeyID: "key"}})
				err := client.RevokeToken(t.Context(), "token", "")
				var retrieveErr *oauth2.RetrieveError
				require.ErrorAs(t, err, &retrieveErr)
				require.Equal(t, tc.wantCode, retrieveErr.ErrorCode)
				require.Equal(t, tc.status, retrieveErr.Response.StatusCode)
				require.Equal(t, tc.body, string(retrieveErr.Body))
			})
		}
	})

	t.Run("revocation_endpoint が discovery にない", func(t *testing.T) {
		server := newAuthTestServer(t, authTestServerOptions{withoutRevocation: true})
		client := NewClient(ClientConfig{Issuer: server.URL, ClientID: "client", ClientSecret: "secret"})
		err := client.RevokeToken(t.Context(), "token", "")
		require.ErrorContains(t, err, "revocation_endpoint")
	})

	t.Run("署名器のエラーを errors.As で取り出せる", func(t *testing.T) {
		server := newAuthTestServer(t, authTestServerOptions{})
		client := NewClient(ClientConfig{Issuer: server.URL, ClientID: "client",
			ClientPrivateKey: &ClientPrivateKey{Key: failingSigner(key), KeyID: "key"}})
		err := client.RevokeToken(t.Context(), "token", "")
		var qe *quotaError
		require.ErrorAs(t, err, &qe)
		require.Empty(t, server.received())
	})
}
