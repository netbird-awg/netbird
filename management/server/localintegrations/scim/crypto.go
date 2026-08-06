package scim

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	tokenPrefix = "nbs_"
	tokenBytes  = 32
)

func newToken() (plain, digest, hint string, err error) {
	secret := make([]byte, tokenBytes)
	if _, err = rand.Read(secret); err != nil {
		return "", "", "", fmt.Errorf("generate SCIM token: %w", err)
	}
	plain = tokenPrefix + base64.RawURLEncoding.EncodeToString(secret)
	digest = tokenDigest(plain)
	hint = plain[:min(len(plain), 12)]
	return plain, digest, hint, nil
}

func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func maskedToken(hint string) string {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		return ""
	}
	return hint + strings.Repeat("*", 24)
}

func keyedLookup(key []byte, value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func fingerprint(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
