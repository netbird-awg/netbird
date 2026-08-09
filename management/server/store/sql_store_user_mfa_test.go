package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

func TestGetAccountLoadsUserMFAState(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		account := newAccountWithId(ctx, "mfa-state", "mfa-state-user", "")
		user := account.Users["mfa-state-user"]
		policyUpdatedAt := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
		lockedUntil := policyUpdatedAt.Add(15 * time.Minute)
		user.MFAPolicy = types.MFAPolicyRequired
		user.MFAPolicyUpdatedAt = &policyUpdatedAt
		user.MFAFailedAttempts = 3
		user.MFALockedUntil = &lockedUntil
		require.NoError(t, store.SaveAccount(ctx, account))

		stored, err := store.GetAccount(ctx, account.Id)
		require.NoError(t, err)
		storedUser := stored.Users[user.Id]
		require.NotNil(t, storedUser)
		require.Equal(t, types.MFAPolicyRequired, storedUser.MFAPolicy)
		require.NotNil(t, storedUser.MFAPolicyUpdatedAt)
		require.True(t, policyUpdatedAt.Equal(*storedUser.MFAPolicyUpdatedAt))
		require.Equal(t, 3, storedUser.MFAFailedAttempts)
		require.NotNil(t, storedUser.MFALockedUntil)
		require.True(t, lockedUntil.Equal(*storedUser.MFALockedUntil))
	})
}

func TestGetAccountNormalizesEmptyUserMFAPolicy(t *testing.T) {
	runTestForAllEngines(t, "", func(t *testing.T, store Store) {
		ctx := context.Background()
		account := newAccountWithId(ctx, "empty-mfa", "empty-mfa-user", "")
		require.NoError(t, store.SaveAccount(ctx, account))

		sqlStore, ok := store.(*SqlStore)
		require.True(t, ok)
		require.NoError(
			t,
			sqlStore.db.Model(&types.User{}).
				Where(idQueryCondition, "empty-mfa-user").
				UpdateColumn("mfa_policy", "").Error,
		)

		stored, err := store.GetAccount(ctx, account.Id)
		require.NoError(t, err)
		require.Equal(
			t,
			types.MFAPolicyInherit,
			stored.Users["empty-mfa-user"].MFAPolicy,
		)
	})
}
