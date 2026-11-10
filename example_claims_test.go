package klon_test

import (
	"context"

	klon "github.com/pocketsign/klon/sdk/go"
)

// SDK の外で、クレームを要求するオプション関数を定義する例。
func ExampleWithIDTokenClaim() {
	withActor := func(subscriptionID string) klon.AuthorizeOptionFunc {
		return klon.WithIDTokenClaim("act", klon.ClaimValue(map[string]string{"sub": subscriptionID}))
	}

	client := klon.NewClient(klon.ClientConfig{Issuer: "https://idp.example.com", ClientID: "client", RedirectURI: "https://rp.example.com/callback"})
	_, _, _ = client.CreateAuthorizationURL(context.Background(),
		klon.AuthorizeOptions{Prompt: []string{klon.PromptLogin, "proxy_register"}},
		withActor("actor-subscription-id"),
	)
}
