package dex

import (
	"context"
	"errors"
	"fmt"

	"github.com/dexidp/dex/storage"
)

// SetMFARequirementResolver configures the per-user native Dex MFA policy.
// A nil resolver preserves Dex's persisted client MFA chain behavior.
func (p *Provider) SetMFARequirementResolver(resolver MFARequirementResolver) {
	p.mfaStorage.setRequirementResolver(resolver)
}

// SetMFAAttemptLimiter configures persistent throttling for native TOTP
// verification attempts. A nil limiter disables the additional throttling.
func (p *Provider) SetMFAAttemptLimiter(limiter MFAAttemptLimiter) {
	p.mu.Lock()
	p.mfaLimiter = limiter
	p.mu.Unlock()
}

// RevokeUserSessions invalidates browser authentication state and refresh
// tokens after an MFA policy change. Already-issued NetBird JWTs are rejected
// separately using the persisted policy-change timestamp.
func (p *Provider) RevokeUserSessions(ctx context.Context, encodedUserID string) error {
	userID, connectorID := decodeConnectorUserID(encodedUserID)
	if connectorID == "" {
		connectorID = LocalConnectorID
	}
	for _, revoke := range []func() error{
		func() error { return p.storage.DeleteAuthSession(ctx, userID, connectorID) },
		func() error { return p.storage.DeleteOfflineSessions(ctx, userID, connectorID) },
	} {
		if err := revoke(); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}
	}
	tokens, err := p.storage.ListRefreshTokens(ctx)
	if err != nil {
		return fmt.Errorf("list refresh tokens: %w", err)
	}
	for _, token := range tokens {
		if token.Claims.UserID != userID || token.ConnectorID != connectorID {
			continue
		}
		if err := p.storage.DeleteRefresh(ctx, token.ID); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("delete refresh token: %w", err)
		}
	}
	return nil
}
