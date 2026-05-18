package klon

import (
	"crypto/sha256"
	"encoding/base64"
)

func computeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
