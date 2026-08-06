package server

import (
	"context"
	"fmt"
	"time"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/store"
)

// persistLocalMfaPolicyChange invalidates existing JWTs in the same database
// transaction that changes the account MFA default. Session revocation can then
// run after commit without leaving old JWTs valid when an external side effect
// fails.
func (am *DefaultAccountManager) persistLocalMfaPolicyChange(ctx context.Context, transaction store.Store, accountID string) error {
	users, err := transaction.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return fmt.Errorf("load users for MFA policy change: %w", err)
	}
	changedAt := time.Now().UTC()
	for _, user := range users {
		if !dex.IsLocalUserID(user.Id) {
			continue
		}
		user.MFAPolicyUpdatedAt = &changedAt
		if err := transaction.SaveUser(ctx, user); err != nil {
			return fmt.Errorf("persist MFA policy change for user %s: %w", user.Id, err)
		}
	}
	return nil
}
