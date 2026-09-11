package klon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

// ClientPrivateKey は private_key_jwt 用の秘密鍵と登録した公開 JWKS の kid。
// サーバー側でのみ使用する。Key は ECDSA P-256 鍵である必要がある。
type ClientPrivateKey struct {
	Key   *ecdsa.PrivateKey
	KeyID string
}

func (c *Client) validateClientAuthentication() error {
	key := c.config.ClientPrivateKey
	if key == nil {
		return nil
	}
	if c.config.ClientSecret != "" {
		return fmt.Errorf("ClientSecret and ClientPrivateKey cannot be configured together")
	}
	if key.Key == nil || key.Key.Curve != elliptic.P256() || strings.TrimSpace(key.KeyID) == "" {
		return fmt.Errorf("ClientPrivateKey requires an ECDSA P-256 key and a non-empty KeyID")
	}
	return nil
}

func (c *Client) setClientAssertion(form url.Values) error {
	key := c.config.ClientPrivateKey
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key.Key},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), key.KeyID))
	if err != nil {
		return fmt.Errorf("failed to create client assertion signer: %w", err)
	}
	now := time.Now()
	assertion, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: c.config.ClientID, Subject: c.config.ClientID,
		Audience: jwt.Audience{c.config.Issuer},
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(time.Minute)),
		ID: oauth2.GenerateVerifier(),
	}).Serialize()
	if err != nil {
		return fmt.Errorf("failed to sign client assertion: %w", err)
	}
	form.Set("client_id", c.config.ClientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	return nil
}

// privateKeyTokenRequest handles the authentication method not supported by oauth2.Config.
func (c *Client) privateKeyTokenRequest(ctx context.Context, endpoint string, form url.Values) (*oauth2.Token, error) {
	if err := c.setClientAssertion(form); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClientFromContext(ctx).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var result struct {
		AccessToken      string `json:"access_token"`
		TokenType        string `json:"token_type"`
		RefreshToken     string `json:"refresh_token"`
		ExpiresIn        int64  `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorURI         string `json:"error_uri"`
	}
	parseErr := json.Unmarshal(body, &result)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || result.Error != "" {
		return nil, &oauth2.RetrieveError{Response: resp, Body: body, ErrorCode: result.Error,
			ErrorDescription: result.ErrorDescription, ErrorURI: result.ErrorURI}
	}
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", parseErr)
	}
	if result.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}
	token := &oauth2.Token{AccessToken: result.AccessToken, TokenType: result.TokenType,
		RefreshToken: result.RefreshToken, ExpiresIn: result.ExpiresIn}
	if token.RefreshToken == "" {
		token.RefreshToken = form.Get("refresh_token")
	}
	if result.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	}
	var extra map[string]any
	if err := json.Unmarshal(body, &extra); err != nil {
		return nil, err
	}
	return token.WithExtra(extra), nil
}
