package idp

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
)

// ResetUserPassword resets a user's password without requiring the old password.
func (m *EmbeddedIdPManager) ResetUserPassword(ctx context.Context, targetUserID, newPassword string) error {
	if err := m.provider.ResetUserPassword(ctx, targetUserID, newPassword); err != nil {
		if m.appMetrics != nil {
			m.appMetrics.IDPMetrics().CountRequestError()
		}
		return err
	}
	log.WithContext(ctx).Debugf("admin reset password for user %s in embedded IdP", targetUserID)
	return nil
}

func (m *EmbeddedIdPManager) SupportsUserPasswordManagement(ctx context.Context, targetUserID string) (bool, error) {
	return m.provider.SupportsUserPasswordManagement(ctx, targetUserID)
}

func (m *EmbeddedIdPManager) SetMFARequirementResolver(resolver dex.MFARequirementResolver) {
	m.provider.SetMFARequirementResolver(resolver)
}

func (m *EmbeddedIdPManager) SetMFAAttemptLimiter(limiter dex.MFAAttemptLimiter) {
	m.provider.SetMFAAttemptLimiter(limiter)
}

func (m *EmbeddedIdPManager) RevokeUserSessions(ctx context.Context, userID string) error {
	return m.provider.RevokeUserSessions(ctx, userID)
}

func (m *EmbeddedIdPManager) IsLDAPConnector(ctx context.Context, connectorID string) (bool, error) {
	connector, err := m.GetConnector(ctx, connectorID)
	if err != nil {
		return false, err
	}
	return connector.Type == "ldap", nil
}
