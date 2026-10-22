package klon

import (
	"context"
	"crypto"
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
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

// ClientPrivateKey は private_key_jwt 用の署名器と登録した公開 JWKS の kid。
// サーバー側でのみ使用する。
type ClientPrivateKey struct {
	// Key は *ecdsa.PrivateKey または KMS 等の crypto.Signer 実装。
	// Public は ECDSA P-256 公開鍵を返し、Sign は SHA-256 ダイジェストを
	// 署名して ASN.1 DER 形式の ECDSA 署名を返す必要がある。
	// crypto.Signer は Context を受け取らないため、通信のタイムアウトは実装側で管理する。
	Key   crypto.Signer
	KeyID string
}

// clientAssertionLifetime はサーバーが許容する最大有効期間 (5 分) より十分短くする。
const clientAssertionLifetime = time.Minute

func (c *Client) validateClientAuthentication() error {
	key := c.config.ClientPrivateKey
	if key == nil {
		return nil
	}
	if c.config.ClientSecret != "" {
		return fmt.Errorf("ClientSecret and ClientPrivateKey cannot be configured together")
	}
	if key.Key == nil || strings.TrimSpace(key.KeyID) == "" {
		return fmt.Errorf("ClientPrivateKey requires an ECDSA P-256 key and a non-empty KeyID")
	}
	// Preserve nil private-key validation after wrapping the key in an interface.
	if privateKey, ok := key.Key.(*ecdsa.PrivateKey); ok && privateKey == nil {
		return fmt.Errorf("ClientPrivateKey requires an ECDSA P-256 key and a non-empty KeyID")
	}
	publicKey, ok := key.Key.Public().(*ecdsa.PublicKey)
	if !ok || publicKey == nil || publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("ClientPrivateKey requires an ECDSA P-256 key and a non-empty KeyID")
	}
	return nil
}

// ClientAssertion は private_key_jwt の client_assertion (RFC 7523) を生成する。
// SDK が対応していない endpoint へクライアント認証付きのリクエストを送る場合に使う。
// aud は Issuer Identifier (RFC 7523bis)、有効期間は 60 秒、jti は毎回ランダムに生成する。
// 署名器が返したエラーは wrap して返すため、errors.As / errors.Is で判別できる。
// ctx は署名器に渡らない。キャンセル済みの場合のみ署名前にエラーを返す。
func (c *Client) ClientAssertion(ctx context.Context) (string, error) {
	if c.config.ClientPrivateKey == nil {
		return "", fmt.Errorf("ClientAssertion requires ClientPrivateKey")
	}
	// discovery で Issuer が IdP の issuer と一致することを確認してから aud に使う。
	// 結果はキャッシュされるため、通信は初回のみ。
	if _, err := c.discover(ctx); err != nil {
		return "", fmt.Errorf("OIDC discovery failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	key := c.config.ClientPrivateKey
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: cryptosigner.Opaque(key.Key)},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), key.KeyID))
	if err != nil {
		return "", fmt.Errorf("failed to create client assertion signer: %w", err)
	}
	now := time.Now()
	assertion, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: c.config.ClientID, Subject: c.config.ClientID,
		Audience: jwt.Audience{c.config.Issuer},
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(clientAssertionLifetime)),
		ID: oauth2.GenerateVerifier(),
	}).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign client assertion: %w", err)
	}
	return assertion, nil
}

// setClientAuthentication は設定された認証方式のクライアント認証パラメータを form に設定する。
// ClientPrivateKey は private_key_jwt、ClientSecret は client_secret_post、いずれもなければ client_id のみを送る。
func (c *Client) setClientAuthentication(ctx context.Context, form url.Values) error {
	form.Set("client_id", c.config.ClientID)
	switch {
	case c.config.ClientPrivateKey != nil:
		assertion, err := c.ClientAssertion(ctx)
		if err != nil {
			return err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	case c.config.ClientSecret != "":
		form.Set("client_secret", c.config.ClientSecret)
	}
	return nil
}

// tokenRequest sends a token request with form-based client authentication.
// oauth2.Config does not support private_key_jwt, so this is used for it and for grants the SDK sends itself.
func (c *Client) tokenRequest(ctx context.Context, endpoint string, form url.Values) (*oauth2.Token, error) {
	if err := c.setClientAuthentication(ctx, form); err != nil {
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
