package idp

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"
)

var (
	lowerCharSet   = "abcdefghijklmnopqrstuvwxyz"
	upperCharSet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	specialCharSet = "!@#$%&*"
	numberSet      = "0123456789"
	allCharSet     = lowerCharSet + upperCharSet + specialCharSet + numberSet
)

type JsonParser struct{}

func (JsonParser) Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func (JsonParser) Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// GeneratePassword generates a password using the operating system's
// cryptographically secure random source.
func GeneratePassword(passwordLength, minSpecialChar, minNum, minUpperCase int) (string, error) {
	if passwordLength <= 0 || minSpecialChar < 0 || minNum < 0 || minUpperCase < 0 {
		return "", fmt.Errorf("invalid password length requirements")
	}
	if minSpecialChar+minNum+minUpperCase > passwordLength {
		return "", fmt.Errorf("minimum character requirements exceed password length")
	}

	password := make([]byte, 0, passwordLength)
	appendRandom := func(charSet string, count int) error {
		for range count {
			index, err := secureRandomIndex(len(charSet))
			if err != nil {
				return err
			}
			password = append(password, charSet[index])
		}
		return nil
	}

	if err := appendRandom(specialCharSet, minSpecialChar); err != nil {
		return "", err
	}
	if err := appendRandom(numberSet, minNum); err != nil {
		return "", err
	}
	if err := appendRandom(upperCharSet, minUpperCase); err != nil {
		return "", err
	}
	if err := appendRandom(allCharSet, passwordLength-len(password)); err != nil {
		return "", err
	}

	for i := len(password) - 1; i > 0; i-- {
		j, err := secureRandomIndex(i + 1)
		if err != nil {
			return "", err
		}
		password[i], password[j] = password[j], password[i]
	}

	return string(password), nil
}

func secureRandomIndex(limit int) (int, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("random selection requires a non-empty character set")
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		return 0, fmt.Errorf("generate secure random value: %w", err)
	}
	return int(value.Int64()), nil
}

// baseURL returns the base url  by concatenating
// the scheme and host components of the parsed URL.
func baseURL(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	return parsedURL.Scheme + "://" + parsedURL.Host
}

const (
	// Provides the env variable name for use with idpTimeout function
	idpTimeoutEnv = "NB_IDP_TIMEOUT"
	// Sets the defaultTimeout to 10s.
	defaultTimeout = 10 * time.Second
)

// idpTimeout returns a timeout value for the IDP
func idpTimeout() time.Duration {
	timeoutStr, ok := os.LookupEnv(idpTimeoutEnv)
	if !ok || timeoutStr == "" {
		return defaultTimeout
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return defaultTimeout
	}
	return timeout
}
