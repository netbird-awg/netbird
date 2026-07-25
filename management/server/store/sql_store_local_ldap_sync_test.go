package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ldapsyncmodel "github.com/netbirdio/netbird/management/server/localintegrations/ldapsync/model"
)

func TestLocalLDAPSyncStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	baseStore, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	testStore, ok := baseStore.(*SqlStore)
	require.True(t, ok)

	config := &ldapsyncmodel.Config{
		AccountID:         "account-a",
		ConnectorID:       "ldap-a",
		Enabled:           true,
		IntervalMinutes:   60,
		SyncScopeGroups:   []string{"netbird"},
		DeprovisionAction: ldapsyncmodel.DeprovisionDisable,
		ConflictPolicy:    ldapsyncmodel.ConflictSkip,
	}
	require.NoError(t, testStore.SaveLDAPSyncConfig(ctx, config, 0))
	require.Equal(t, int64(1), config.Revision)

	loaded, err := testStore.GetLDAPSyncConfig(ctx, config.AccountID, config.ConnectorID)
	require.NoError(t, err)
	require.Equal(t, []string{"netbird"}, loaded.SyncScopeGroups)

	loaded.IntervalMinutes = 120
	require.NoError(t, testStore.SaveLDAPSyncConfig(ctx, loaded, 1))
	require.Equal(t, int64(2), loaded.Revision)
	require.ErrorContains(t, testStore.SaveLDAPSyncConfig(ctx, loaded, 1), "revision conflict")

	now := time.Now().UTC()
	firstRun := &ldapsyncmodel.Run{
		ID:             "run-a",
		AccountID:      config.AccountID,
		ConnectorID:    config.ConnectorID,
		Status:         ldapsyncmodel.RunStatusQueued,
		Trigger:        ldapsyncmodel.RunTriggerManual,
		ConfigRevision: loaded.Revision,
		QueuedAt:       now,
	}
	require.NoError(t, testStore.CreateLDAPSyncRun(ctx, firstRun))
	require.ErrorContains(t, testStore.CreateLDAPSyncRun(ctx, &ldapsyncmodel.Run{
		ID:             "run-duplicate",
		AccountID:      config.AccountID,
		ConnectorID:    config.ConnectorID,
		Status:         ldapsyncmodel.RunStatusQueued,
		Trigger:        ldapsyncmodel.RunTriggerManual,
		ConfigRevision: loaded.Revision,
		QueuedAt:       now.Add(time.Second),
	}), "sync_already_running")

	depth, err := testStore.CountLDAPSyncRuns(ctx, ldapsyncmodel.RunStatusQueued)
	require.NoError(t, err)
	require.Equal(t, int64(1), depth)

	claimed, err := testStore.ClaimLDAPSyncRun(ctx, now, time.Minute, "worker-a")
	require.NoError(t, err)
	require.Equal(t, firstRun.ID, claimed.ID)
	require.Equal(t, ldapsyncmodel.RunStatusRunning, claimed.Status)
	require.Equal(t, "worker-a", claimed.LeaseOwner)
	renewed, err := testStore.RenewLDAPSyncRunLease(ctx, config.AccountID, config.ConnectorID, claimed.ID, "worker-a", now.Add(30*time.Second), time.Minute)
	require.NoError(t, err)
	require.True(t, renewed)
	renewed, err = testStore.RenewLDAPSyncRunLease(ctx, config.AccountID, config.ConnectorID, claimed.ID, "worker-stale", now.Add(30*time.Second), time.Minute)
	require.NoError(t, err)
	require.False(t, renewed)

	finishedAt := now.Add(time.Second)
	claimed.Status = ldapsyncmodel.RunStatusSuccess
	claimed.FinishedAt = &finishedAt
	claimed.LeaseUntil = nil
	claimed.LeaseOwner = ""
	owned, err := testStore.UpdateLDAPSyncRunOwned(ctx, claimed, "worker-a")
	require.NoError(t, err)
	require.True(t, owned)
	require.NoError(t, testStore.CreateLDAPSyncRun(ctx, &ldapsyncmodel.Run{
		ID:             "run-b",
		AccountID:      config.AccountID,
		ConnectorID:    config.ConnectorID,
		Status:         ldapsyncmodel.RunStatusQueued,
		Trigger:        ldapsyncmodel.RunTriggerManual,
		ConfigRevision: loaded.Revision,
		QueuedAt:       now.Add(2 * time.Second),
	}))

	claimedRuns := make(chan *ldapsyncmodel.Run, 2)
	claimErrors := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for range 2 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			claimedRun, claimErr := testStore.ClaimLDAPSyncRun(ctx, now.Add(3*time.Second), time.Minute, "worker-concurrent")
			claimedRuns <- claimedRun
			claimErrors <- claimErr
		}()
	}
	waitGroup.Wait()
	close(claimedRuns)
	close(claimErrors)
	for claimErr := range claimErrors {
		require.NoError(t, claimErr)
	}
	claimCount := 0
	var claimedRunB *ldapsyncmodel.Run
	for claimedRun := range claimedRuns {
		if claimedRun != nil {
			claimCount++
			require.Equal(t, "run-b", claimedRun.ID)
			claimedRunB = claimedRun
		}
	}
	require.Equal(t, 1, claimCount, "concurrent workers must claim an active run only once")
	require.NotNil(t, claimedRunB)
	claimedRunB.Status = ldapsyncmodel.RunStatusSuccess
	claimedRunB.FinishedAt = &finishedAt
	claimedRunB.LeaseUntil = nil
	claimedRunB.LeaseOwner = ""
	owned, err = testStore.UpdateLDAPSyncRunOwned(ctx, claimedRunB, "worker-concurrent")
	require.NoError(t, err)
	require.True(t, owned)

	require.NoError(t, testStore.CreateLDAPSyncRun(ctx, &ldapsyncmodel.Run{
		ID:             "run-c",
		AccountID:      config.AccountID,
		ConnectorID:    config.ConnectorID,
		Status:         ldapsyncmodel.RunStatusQueued,
		Trigger:        ldapsyncmodel.RunTriggerManual,
		ConfigRevision: loaded.Revision,
		QueuedAt:       now.Add(4 * time.Second),
	}))
	cancelled, err := testStore.CancelLDAPSyncRun(ctx, config.AccountID, config.ConnectorID, "run-c", now.Add(5*time.Second))
	require.NoError(t, err)
	require.Equal(t, ldapsyncmodel.RunStatusCancelled, cancelled.Status)
	require.NotNil(t, cancelled.FinishedAt)

	object := &ldapsyncmodel.Object{
		AccountID:         config.AccountID,
		ConnectorID:       config.ConnectorID,
		ObjectType:        ldapsyncmodel.ObjectTypeUser,
		ExternalID:        "external-hmac",
		NetBirdObjectID:   "user-a",
		SourceFingerprint: "fingerprint-a",
		LastSeenAt:        now,
		ManagedFields:     []string{"name"},
		Status:            ldapsyncmodel.ObjectStatusActive,
	}
	require.NoError(t, testStore.SaveLDAPSyncObjects(ctx, []*ldapsyncmodel.Object{object}))
	object.SourceFingerprint = "fingerprint-b"
	object.LastSeenAt = finishedAt
	require.NoError(t, testStore.SaveLDAPSyncObjects(ctx, []*ldapsyncmodel.Object{object}))

	objects, err := testStore.GetLDAPSyncObjects(ctx, config.AccountID, config.ConnectorID, ldapsyncmodel.ObjectTypeUser)
	require.NoError(t, err)
	require.Len(t, objects, 1)
	require.Equal(t, "fingerprint-b", objects[0].SourceFingerprint)
}

func TestLocalLDAPSyncRunLeaseRejectsStaleWorkerFinalization(t *testing.T) {
	ctx := context.Background()
	baseStore, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	testStore, ok := baseStore.(*SqlStore)
	require.True(t, ok)

	now := time.Now().UTC()
	run := &ldapsyncmodel.Run{
		ID:             "run-lease",
		AccountID:      "account-a",
		ConnectorID:    "ldap-a",
		Status:         ldapsyncmodel.RunStatusQueued,
		Trigger:        ldapsyncmodel.RunTriggerManual,
		ConfigRevision: 1,
		QueuedAt:       now,
	}
	require.NoError(t, testStore.CreateLDAPSyncRun(ctx, run))

	stale, err := testStore.ClaimLDAPSyncRun(ctx, now, time.Second, "worker-stale")
	require.NoError(t, err)
	require.NotNil(t, stale)
	current, err := testStore.ClaimLDAPSyncRun(ctx, now.Add(2*time.Second), time.Minute, "worker-current")
	require.NoError(t, err)
	require.NotNil(t, current)

	stale.Status = ldapsyncmodel.RunStatusSuccess
	stale.LeaseUntil = nil
	stale.LeaseOwner = ""
	owned, err := testStore.UpdateLDAPSyncRunOwned(ctx, stale, "worker-stale")
	require.NoError(t, err)
	require.False(t, owned)

	current.Status = ldapsyncmodel.RunStatusSuccess
	current.LeaseUntil = nil
	current.LeaseOwner = ""
	owned, err = testStore.UpdateLDAPSyncRunOwned(ctx, current, "worker-current")
	require.NoError(t, err)
	require.True(t, owned)
}
