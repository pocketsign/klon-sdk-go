package klon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ClientConfig は [Client] の生成に必要な設定を保持する。
type ClientConfig struct {
	Issuer           string            // OIDC Issuer URL。
	ClientID         string            // クライアント ID。
	ClientSecret     string            // 共有シークレット認証。ClientPrivateKey と併用不可。
	ClientPrivateKey *ClientPrivateKey // private_key_jwt 認証。認証情報が両方未指定なら Public Client。
	RedirectURI      string            // 認可レスポンスのリダイレクト先 URI。
}

// AuthorizeOptions は [Client.CreateAuthorizationURL] の認可リクエストパラメータを指定する。
type AuthorizeOptions struct {
	Scopes                []string                   // デフォルト: ["openid"]
	AuthorizationDetails  []AuthorizationDetailInput // RFC 9396 Rich Authorization Requests
	AcrValues             []string
	Prompt                []string
	MaxAge                *int // 認証の最大経過時間 (秒)
	GrantManagementAction GrantManagementAction
	UsePAR                bool // RFC 9126 Pushed Authorization Requests
}

// AuthorizationSession は認可コード交換に必要なフロー状態を保持する。
// JSON シリアライズしてセッションストレージに保存し、コールバック時に復元する。
type AuthorizationSession struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
	MaxAge       *int   `json:"max_age,omitempty"`
}

// TokenSet はトークンエンドポイントから取得したトークン群を保持する。
type TokenSet struct {
	AccessToken          string
	TokenType            string // 通常 "Bearer"
	ExpiresIn            *int   // 有効期限 (秒)
	RefreshToken         string
	IDToken              string
	IDTokenClaims        *IDTokenClaims // ID Token のデコード済みクレーム。IDToken が存在する場合にセットされる。
	Scope                string
	AuthorizationDetails []AuthorizationDetail
}

// Client は KLON IdP と連携する OIDC クライアント。
// OIDC discovery の結果は内部でキャッシュされ、複数の goroutine から安全に利用できる。
type Client struct {
	config   ClientConfig
	mu       sync.Mutex
	provider *oidc.Provider
}

// NewClient は指定した設定で [Client] を生成する。
func NewClient(config ClientConfig) *Client {
	return &Client{config: config}
}

func (c *Client) discover(ctx context.Context) (*oidc.Provider, error) {
	if err := c.validateClientAuthentication(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.provider != nil {
		return c.provider, nil
	}

	provider, err := oidc.NewProvider(ctx, c.config.Issuer)
	if err != nil {
		return nil, err
	}

	c.provider = provider
	return provider, nil
}

func (c *Client) oauth2Config(scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.config.ClientID,
		ClientSecret: c.config.ClientSecret,
		RedirectURL:  c.config.RedirectURI,
		Scopes:       scopes,
	}
}

// CreateAuthorizationURL は PKCE 付きの認可 URL を生成する。
// 返された session はコールバック処理に必要なのでセッションストレージに保存すること。
func (c *Client) CreateAuthorizationURL(ctx context.Context, opts ...AuthorizeOptions) (*url.URL, *AuthorizationSession, error) {
	var opt AuthorizeOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	if err := validatePromptValues(opt.Prompt); err != nil {
		return nil, nil, err
	}

	provider, err := c.discover(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	codeVerifier := oauth2.GenerateVerifier()
	state := oauth2.GenerateVerifier()
	nonce := oauth2.GenerateVerifier()

	// 配列から文字列を構築
	scopes := opt.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	cfg := c.oauth2Config(scopes)

	var adJSON string
	if len(opt.AuthorizationDetails) > 0 {
		var err error
		adJSON, err = BuildAuthorizationDetails(opt.AuthorizationDetails)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to build authorization_details: %w", err)
		}
	}
	acrValues := strings.Join(opt.AcrValues, " ")
	prompt := BuildPrompt(opt.Prompt...)

	var endpoint struct {
		AuthURL  string `json:"authorization_endpoint"`
		TokenURL string `json:"token_endpoint"`
		PARURL   string `json:"pushed_authorization_request_endpoint"`
	}
	if err := provider.Claims(&endpoint); err != nil {
		return nil, nil, fmt.Errorf("failed to read provider claims: %w", err)
	}
	cfg.Endpoint = oauth2.Endpoint{
		AuthURL:  endpoint.AuthURL,
		TokenURL: endpoint.TokenURL,
	}

	authCodeOpts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(codeVerifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	}

	if adJSON != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("authorization_details", adJSON))
	}
	if acrValues != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("acr_values", acrValues))
	}
	if prompt != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("prompt", prompt))
	}
	if opt.MaxAge != nil {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("max_age", fmt.Sprintf("%d", *opt.MaxAge)))
	}
	if opt.GrantManagementAction != "" {
		authCodeOpts = append(authCodeOpts, oauth2.SetAuthURLParam("grant_management_action", string(opt.GrantManagementAction)))
	}

	var authURL *url.URL
	if opt.UsePAR {
		if endpoint.PARURL == "" {
			return nil, nil, fmt.Errorf("authorization server does not expose a pushed_authorization_request_endpoint")
		}
		requestURI, err := c.pushedAuthorizationRequest(ctx, endpoint.PARURL, state, codeVerifier, nonce, opt)
		if err != nil {
			return nil, nil, fmt.Errorf("PAR request failed: %w", err)
		}
		authURL, err = url.Parse(endpoint.AuthURL)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse authorization endpoint: %w", err)
		}
		q := authURL.Query()
		q.Set("client_id", c.config.ClientID)
		q.Set("request_uri", requestURI)
		authURL.RawQuery = q.Encode()
	} else {
		rawURL := cfg.AuthCodeURL(state, authCodeOpts...)
		authURL, err = url.Parse(rawURL)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse authorization URL: %w", err)
		}
	}

	session := &AuthorizationSession{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: codeVerifier,
		RedirectURI:  c.config.RedirectURI,
	}
	if opt.MaxAge != nil {
		maxAge := *opt.MaxAge
		session.MaxAge = &maxAge
	}

	return authURL, session, nil
}

// ExchangeCode は認可コードをトークンに交換する。
// PKCE 検証、nonce 検証、ID トークン検証を行う。
func (c *Client) ExchangeCode(ctx context.Context, code string, state string, session *AuthorizationSession) (*TokenSet, error) {
	if state != session.State {
		return nil, fmt.Errorf("state mismatch: expected %q, got %q", session.State, state)
	}

	provider, err := c.discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	cfg := c.oauth2Config(nil)
	var endpoint struct {
		AuthURL  string `json:"authorization_endpoint"`
		TokenURL string `json:"token_endpoint"`
	}
	if err := provider.Claims(&endpoint); err != nil {
		return nil, fmt.Errorf("failed to read provider claims: %w", err)
	}
	cfg.Endpoint = oauth2.Endpoint{
		AuthURL:  endpoint.AuthURL,
		TokenURL: endpoint.TokenURL,
	}

	var token *oauth2.Token
	if c.config.ClientPrivateKey != nil {
		token, err = c.privateKeyTokenRequest(ctx, endpoint.TokenURL, url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {session.RedirectURI}, "code_verifier": {session.CodeVerifier},
		})
	} else {
		token, err = cfg.Exchange(ctx, code, oauth2.VerifierOption(session.CodeVerifier))
	}
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, claims, err := c.verifyIDToken(ctx, provider, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("ID token verification failed: %w", err)
	}

	if idToken.Nonce != session.Nonce {
		return nil, fmt.Errorf("nonce mismatch: expected %q, got %q", session.Nonce, idToken.Nonce)
	}

	if err := validateMaxAge(session.MaxAge, claims.AuthTime); err != nil {
		return nil, err
	}

	tokenSet := &TokenSet{
		AccessToken:   token.AccessToken,
		TokenType:     token.TokenType,
		RefreshToken:  token.RefreshToken,
		IDToken:       rawIDToken,
		IDTokenClaims: claims,
	}

	if !token.Expiry.IsZero() {
		expiresIn := int(token.ExpiresIn)
		tokenSet.ExpiresIn = &expiresIn
	}

	if scope, ok := token.Extra("scope").(string); ok {
		tokenSet.Scope = scope
	}

	if rawAD, ok := token.Extra("authorization_details").([]any); ok {
		tokenSet.AuthorizationDetails = parseTokenAuthorizationDetails(rawAD)
	}

	return tokenSet, nil
}

// RefreshToken はリフレッシュトークンでアクセストークンを更新する。
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error) {
	provider, err := c.discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}

	cfg := c.oauth2Config(nil)
	var endpoint struct {
		AuthURL  string `json:"authorization_endpoint"`
		TokenURL string `json:"token_endpoint"`
	}
	if err := provider.Claims(&endpoint); err != nil {
		return nil, fmt.Errorf("failed to read provider claims: %w", err)
	}
	cfg.Endpoint = oauth2.Endpoint{
		AuthURL:  endpoint.AuthURL,
		TokenURL: endpoint.TokenURL,
	}

	var token *oauth2.Token
	if c.config.ClientPrivateKey != nil {
		token, err = c.privateKeyTokenRequest(ctx, endpoint.TokenURL, url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
		})
	} else {
		token, err = cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	}
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	tokenSet := &TokenSet{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
	}

	if !token.Expiry.IsZero() {
		expiresIn := int(token.ExpiresIn)
		tokenSet.ExpiresIn = &expiresIn
	}

	if rawIDToken, ok := token.Extra("id_token").(string); ok {
		tokenSet.IDToken = rawIDToken
		_, claims, err := c.verifyIDToken(ctx, provider, rawIDToken)
		if err != nil {
			return nil, fmt.Errorf("ID token verification failed: %w", err)
		}
		tokenSet.IDTokenClaims = claims
	}

	if scope, ok := token.Extra("scope").(string); ok {
		tokenSet.Scope = scope
	}

	if rawAD, ok := token.Extra("authorization_details").([]any); ok {
		tokenSet.AuthorizationDetails = parseTokenAuthorizationDetails(rawAD)
	}

	return tokenSet, nil
}

func (c *Client) pushedAuthorizationRequest(
	ctx context.Context,
	parEndpoint string,
	state string,
	codeVerifier string,
	nonce string,
	opt AuthorizeOptions,
) (string, error) {
	form := url.Values{}
	form.Set("client_id", c.config.ClientID)
	if c.config.ClientPrivateKey != nil {
		if err := c.setClientAssertion(form); err != nil {
			return "", err
		}
	} else if c.config.ClientSecret != "" {
		form.Set("client_secret", c.config.ClientSecret)
	}
	form.Set("response_type", "code")
	form.Set("redirect_uri", c.config.RedirectURI)
	form.Set("code_challenge_method", "S256")
	form.Set("state", state)
	form.Set("nonce", nonce)

	scopes := opt.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	form.Set("scope", strings.Join(scopes, " "))
	form.Set("code_challenge", computeS256Challenge(codeVerifier))

	if len(opt.AuthorizationDetails) > 0 {
		adJSON, err := BuildAuthorizationDetails(opt.AuthorizationDetails)
		if err != nil {
			return "", fmt.Errorf("failed to build authorization_details: %w", err)
		}
		form.Set("authorization_details", adJSON)
	}
	if len(opt.AcrValues) > 0 {
		form.Set("acr_values", strings.Join(opt.AcrValues, " "))
	}
	if len(opt.Prompt) > 0 {
		form.Set("prompt", BuildPrompt(opt.Prompt...))
	}
	if opt.MaxAge != nil {
		form.Set("max_age", fmt.Sprintf("%d", *opt.MaxAge))
	}
	if opt.GrantManagementAction != "" {
		form.Set("grant_management_action", string(opt.GrantManagementAction))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create PAR request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpClient := httpClientFromContext(ctx)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("PAR request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read PAR response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("PAR request returned status %d: %s", resp.StatusCode, string(body))
	}

	var parResp struct {
		RequestURI string `json:"request_uri"`
		ExpiresIn  int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parResp); err != nil {
		return "", fmt.Errorf("failed to parse PAR response: %w", err)
	}

	if parResp.RequestURI == "" {
		return "", fmt.Errorf("PAR response missing request_uri")
	}

	return parResp.RequestURI, nil
}

func (c *Client) verifyIDToken(ctx context.Context, provider *oidc.Provider, rawIDToken string) (*oidc.IDToken, *IDTokenClaims, error) {
	verifier := provider.VerifierContext(ctx, &oidc.Config{
		ClientID: c.config.ClientID,
	})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, nil, err
	}

	var claims IDTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, nil, fmt.Errorf("failed to decode ID token claims: %w", err)
	}
	return idToken, &claims, nil
}

func validateMaxAge(maxAge *int, authTime int64) error {
	if maxAge == nil {
		return nil
	}
	if authTime == 0 {
		return fmt.Errorf("auth_time is required when max_age is specified")
	}
	if authTime+int64(*maxAge) < time.Now().Unix() {
		return fmt.Errorf("auth_time exceeds max_age")
	}
	return nil
}

func validatePromptValues(prompts []string) error {
	if len(prompts) <= 1 {
		return nil
	}
	seen := make(map[string]struct{}, len(prompts))
	for _, prompt := range prompts {
		seen[prompt] = struct{}{}
	}
	if _, ok := seen[PromptNone]; ok && len(seen) > 1 {
		return fmt.Errorf("prompt=none cannot be combined with other prompt values")
	}
	return nil
}

func httpClientFromContext(ctx context.Context) *http.Client {
	if ctx != nil {
		if client, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && client != nil {
			return client
		}
	}
	return http.DefaultClient
}

func parseTokenAuthorizationDetails(raw []any) []AuthorizationDetail {
	var result []AuthorizationDetail
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}

		b, err := json.Marshal(m)
		if err != nil {
			continue
		}

		var detail AuthorizationDetail
		if err := json.Unmarshal(b, &detail); err != nil {
			continue
		}

		if detail.Type != "urn:klon:resource_access" {
			continue
		}

		result = append(result, detail)
	}
	return result
}
