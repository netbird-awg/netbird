package server

import (
	"context"
	"fmt"
	"time"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	maxNativeMFAFailures = 5
	nativeMFALockout     = 15 * time.Minute
)

type mfaPolicyService struct {
	store store.Store
	idp   *idp.EmbeddedIdPManager
	now   func() time.Time
}

func newMFAPolicyService(dataStore store.Store, embeddedIDP *idp.EmbeddedIdPManager) *mfaPolicyService {
	return &mfaPolicyService{
		store: dataStore,
		idp:   embeddedIDP,
		now:   time.Now,
	}
}

func (s *mfaPolicyService) Requirement(ctx context.Context, rawUserID, connectorID string) (bool, error) {
	eligible, err := s.isEligibleConnector(ctx, connectorID)
	if err != nil {
		return false, err
	}
	if !eligible {
		return false, nil
	}

	user, err := s.getUser(ctx, store.LockingStrengthNone, rawUserID, connectorID)
	if err != nil {
		if statusErr, ok := status.FromError(err); ok && statusErr.Type() == status.NotFound {
			// First-time embedded IdP users are authenticated before NetBird creates
			// their management user record. They have no per-user override yet, so
			// use the connector default and let account provisioning complete.
			return false, nil
		}
		return false, err
	}
	switch user.MFAPolicy.Normalized() {
	case types.MFAPolicyRequired:
		return true, nil
	case types.MFAPolicyDisabled:
		return false, nil
	case types.MFAPolicyInherit:
		if connectorID != "local" {
			return false, nil
		}
		settings, err := s.store.GetAccountSettings(ctx, store.LockingStrengthNone, user.AccountID)
		if err != nil {
			return false, fmt.Errorf("get account MFA settings: %w", err)
		}
		if settings == nil {
			return false, fmt.Errorf("account MFA settings are unavailable")
		}
		return settings.LocalMfaEnabled, nil
	default:
		return false, fmt.Errorf("unsupported MFA policy %q", user.MFAPolicy)
	}
}

func (s *mfaPolicyService) Check(ctx context.Context, rawUserID, connectorID string) (time.Duration, error) {
	user, err := s.getUser(ctx, store.LockingStrengthNone, rawUserID, connectorID)
	if err != nil {
		return 0, err
	}
	if user.MFALockedUntil == nil {
		return 0, nil
	}
	retryAfter := user.MFALockedUntil.Sub(s.now())
	if retryAfter <= 0 {
		return 0, nil
	}
	return retryAfter, nil
}

func (s *mfaPolicyService) RecordFailure(ctx context.Context, rawUserID, connectorID string) error {
	return s.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		user, err := s.getUserFromStore(ctx, transaction, store.LockingStrengthUpdate, rawUserID, connectorID)
		if err != nil {
			return err
		}

		now := s.now().UTC()
		if user.MFALockedUntil != nil {
			if now.Before(*user.MFALockedUntil) {
				return nil
			}
			user.MFALockedUntil = nil
			user.MFAFailedAttempts = 0
		}

		user.MFAFailedAttempts++
		if user.MFAFailedAttempts >= maxNativeMFAFailures {
			lockedUntil := now.Add(nativeMFALockout)
			user.MFALockedUntil = &lockedUntil
			user.MFAFailedAttempts = 0
		}
		return transaction.SaveUser(ctx, user)
	})
}

func (s *mfaPolicyService) Clear(ctx context.Context, rawUserID, connectorID string) error {
	return s.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		user, err := s.getUserFromStore(ctx, transaction, store.LockingStrengthUpdate, rawUserID, connectorID)
		if err != nil {
			return err
		}
		if user.MFAFailedAttempts == 0 && user.MFALockedUntil == nil {
			return nil
		}
		user.MFAFailedAttempts = 0
		user.MFALockedUntil = nil
		return transaction.SaveUser(ctx, user)
	})
}

func (s *mfaPolicyService) isEligibleConnector(ctx context.Context, connectorID string) (bool, error) {
	if connectorID == "local" {
		return true, nil
	}
	if s.idp == nil {
		return false, fmt.Errorf("embedded IdP manager is unavailable")
	}
	return s.idp.IsLDAPConnector(ctx, connectorID)
}

func (s *mfaPolicyService) getUser(ctx context.Context, strength store.LockingStrength, rawUserID, connectorID string) (*types.User, error) {
	return s.getUserFromStore(ctx, s.store, strength, rawUserID, connectorID)
}

func (s *mfaPolicyService) getUserFromStore(ctx context.Context, dataStore store.Store, strength store.LockingStrength, rawUserID, connectorID string) (*types.User, error) {
	encodedUserID := dex.EncodeDexUserID(rawUserID, connectorID)
	user, err := dataStore.GetUserByUserID(ctx, strength, encodedUserID)
	if err != nil {
		return nil, fmt.Errorf("get MFA user %s via connector %s: %w", rawUserID, connectorID, err)
	}
	return user, nil
}
