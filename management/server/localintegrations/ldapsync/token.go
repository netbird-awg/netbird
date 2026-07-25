package ldapsync

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	ldapsyncmodel "github.com/netbirdio/netbird/management/server/localintegrations/ldapsync/model"
	"github.com/netbirdio/netbird/shared/management/status"
)

const confirmationTokenTTL = 10 * time.Minute

type confirmationClaims struct {
	AccountID         string `json:"account_id"`
	ConnectorID       string `json:"connector_id"`
	ConfigRevision    int64  `json:"config_revision"`
	SourceFingerprint string `json:"source_fingerprint"`
	ExpiresAt         int64  `json:"expires_at"`
}

func (s *Service) issueConfirmationToken(config *ldapsyncmodel.Config, sourceFingerprint string) (string, time.Time, error) {
	expiresAt := time.Now().UTC().Add(confirmationTokenTTL)
	claims := confirmationClaims{
		AccountID:         config.AccountID,
		ConnectorID:       config.ConnectorID,
		ConfigRevision:    config.Revision,
		SourceFingerprint: sourceFingerprint,
		ExpiresAt:         expiresAt.Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, status.Errorf(status.Internal, "failed to create high-risk confirmation token")
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	signature := s.signConfirmationPayload(encoded)
	return encoded + "." + signature, expiresAt, nil
}

func (s *Service) validateConfirmationToken(token string, config *ldapsyncmodel.Config, sourceFingerprint string) error {
	payload, signature, ok := strings.Cut(token, ".")
	if !ok || payload == "" || signature == "" {
		return status.Errorf(status.PreconditionFailed, "high-risk synchronization requires a valid preview confirmation token")
	}
	expectedSignature := s.signConfirmationPayload(payload)
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return status.Errorf(status.PreconditionFailed, "high-risk confirmation token is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return status.Errorf(status.PreconditionFailed, "high-risk confirmation token is invalid")
	}
	var claims confirmationClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return status.Errorf(status.PreconditionFailed, "high-risk confirmation token is invalid")
	}
	if time.Now().UTC().Unix() >= claims.ExpiresAt {
		return status.Errorf(status.PreconditionFailed, "high-risk confirmation token has expired")
	}
	if claims.AccountID != config.AccountID || claims.ConnectorID != config.ConnectorID || claims.ConfigRevision != config.Revision || claims.SourceFingerprint != sourceFingerprint {
		return status.Errorf(status.PreconditionFailed, "LDAP data or synchronization configuration changed; generate a new preview")
	}
	return nil
}

func (s *Service) signConfirmationPayload(payload string) string {
	mac := hmac.New(sha256.New, s.syncKey)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func confirmationTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum[:])
}
