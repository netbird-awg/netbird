package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	scimmodel "github.com/netbirdio/netbird/management/server/localintegrations/scim/model"
)

func TestLocalSCIMPersistenceKeepsNewerPendingRevision(t *testing.T) {
	ctx := context.Background()
	baseStore, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	defer cleanup()

	repository, ok := baseStore.(interface {
		CreateSCIMIntegration(context.Context, *scimmodel.Integration) error
		GetSCIMIntegration(context.Context, string, uint64) (*scimmodel.Integration, error)
		SaveSCIMResourceAndQueue(context.Context, *scimmodel.Resource, time.Time) error
		ClaimSCIMIntegration(context.Context, time.Time, time.Duration, string) (*scimmodel.Integration, error)
		FinishSCIMIntegrationSync(context.Context, uint64, string, int64, scimmodel.SyncResult) (bool, error)
	})
	require.True(t, ok)

	integration := &scimmodel.Integration{
		AccountID: "account",
		Provider:  "generic",
		TokenHash: "token-hash",
		TokenHint: "nbs_hint",
		Enabled:   true,
	}
	require.NoError(t, repository.CreateSCIMIntegration(ctx, integration))

	now := time.Now().UTC()
	require.NoError(t, repository.SaveSCIMResourceAndQueue(ctx, &scimmodel.Resource{
		ID:               "user-1",
		IntegrationID:    integration.ID,
		ResourceType:     scimmodel.ResourceTypeUser,
		EncryptedPayload: "ciphertext",
	}, now))
	claimed, err := repository.ClaimSCIMIntegration(ctx, now, time.Minute, "worker-1")
	require.NoError(t, err)
	require.NotNil(t, claimed)
	claimedRevision := claimed.SyncRevision

	require.NoError(t, repository.SaveSCIMResourceAndQueue(ctx, &scimmodel.Resource{
		ID:               "user-2",
		IntegrationID:    integration.ID,
		ResourceType:     scimmodel.ResourceTypeUser,
		EncryptedPayload: "ciphertext-2",
	}, now.Add(time.Second)))

	owned, err := repository.FinishSCIMIntegrationSync(ctx, integration.ID, "worker-1", claimedRevision, scimmodel.SyncResult{
		Succeeded: true,
		SyncedAt:  now.Add(2 * time.Second),
	})
	require.NoError(t, err)
	require.True(t, owned)

	current, err := repository.GetSCIMIntegration(ctx, integration.AccountID, integration.ID)
	require.NoError(t, err)
	require.NotNil(t, current.PendingAt, "a newer SCIM event must remain pending")
	require.Greater(t, current.SyncRevision, claimedRevision)

	nextClaim, err := repository.ClaimSCIMIntegration(ctx, now.Add(3*time.Second), time.Minute, "worker-2")
	require.NoError(t, err)
	require.NotNil(t, nextClaim)
	require.Equal(t, current.SyncRevision, nextClaim.SyncRevision)
}
