package klon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

// RevokeToken はアクセストークンまたはリフレッシュトークンを失効させる (RFC 7009)。
// tokenTypeHint には "access_token" / "refresh_token" を指定できる。不要なら空文字列。
// IdP がエラーを返した場合は *oauth2.RetrieveError を返す。
func (c *Client) RevokeToken(ctx context.Context, token, tokenTypeHint string) error {
	provider, err := c.discover(ctx)
	if err != nil {
		return fmt.Errorf("OIDC discovery failed: %w", err)
	}
	var endpoint struct {
		RevocationURL string `json:"revocation_endpoint"`
	}
	if err := provider.Claims(&endpoint); err != nil {
		return fmt.Errorf("failed to read provider claims: %w", err)
	}
	if endpoint.RevocationURL == "" {
		return fmt.Errorf("authorization server does not expose a revocation_endpoint")
	}

	form := url.Values{"token": {token}}
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	if err := c.setClientAuthentication(ctx, form); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.RevocationURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create revocation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClientFromContext(ctx).Do(req)
	if err != nil {
		return fmt.Errorf("revocation request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("failed to read revocation response: %w", err)
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var result struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ErrorURI         string `json:"error_uri"`
	}
	_ = json.Unmarshal(body, &result)
	return &oauth2.RetrieveError{Response: resp, Body: body, ErrorCode: result.Error,
		ErrorDescription: result.ErrorDescription, ErrorURI: result.ErrorURI}
}
