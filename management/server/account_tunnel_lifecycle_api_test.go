package server

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	managementtunnel "github.com/netbirdio/netbird/management/server/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	sharedstatus "github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/util/crypt"
)

func TestTunnelLifecycleManagerPersistsAndFansOutOnlyChangedTransitions(
	t *testing.T,
) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	ctx := context.Background()
	accountID, err := manager.GetAccountIDByUserID(
		ctx,
		auth.UserAuth{UserId: userID},
	)
	require.NoError(t, err)

	settings, err := manager.Store.GetAccountSettings(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	settings.DNSDomain = "preserved.example"
	settings.LocalMfaEnabled = true
	require.NoError(t, manager.Store.SaveAccountSettings(
		ctx,
		accountID,
		settings,
	))

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	peer, _, _, _, err := manager.AddPeer(
		ctx,
		accountID,
		"",
		userID,
		&nbpeer.Peer{
			Key:  key.PublicKey().String(),
			Meta: nbpeer.PeerSystemMeta{Hostname: "lifecycle-fanout"},
		},
		false,
	)
	require.NoError(t, err)
	require.NotEmpty(t, peer.ID)
	controller := gomock.NewController(t)
	networkMapController := network_map.NewMockController(controller)
	fanout := make(chan struct{})
	networkMapController.EXPECT().
		UpdateAccountPeers(
			gomock.Any(),
			accountID,
			gomock.Any(),
		).
		DoAndReturn(func(context.Context, string, types.UpdateReason) error {
			close(fanout)
			return nil
		}).
		Times(1)
	manager.networkMapController = networkMapController

	networkBefore, err := manager.Store.GetAccountNetwork(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	request := managementtunnel.LifecycleRequest{
		Action:          managementtunnel.LifecycleActionStage,
		ProtocolVersion: "awg2",
	}
	staged, err := manager.UpdateTunnelLifecycle(
		ctx,
		accountID,
		userID,
		request,
	)
	require.NoError(t, err)
	require.True(t, staged.Changed)
	require.NotNil(t, staged.Settings.TunnelProfilePending)
	require.Equal(t, uint64(1), staged.Settings.TunnelProfilePending.Revision)
	require.Equal(t, "preserved.example", staged.Settings.DNSDomain)
	require.True(t, staged.Settings.LocalMfaEnabled)
	select {
	case <-fanout:
	case <-time.After(3 * time.Second):
		t.Fatal("changed lifecycle transition did not fan out")
	}

	networkAfter, err := manager.Store.GetAccountNetwork(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	require.Equal(t, networkBefore.Serial+1, networkAfter.Serial)

	repeated, err := manager.UpdateTunnelLifecycle(
		ctx,
		accountID,
		userID,
		request,
	)
	require.NoError(t, err)
	require.False(t, repeated.Changed)
	networkRepeated, err := manager.Store.GetAccountNetwork(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	require.Equal(t, networkAfter.Serial, networkRepeated.Serial)

	require.Eventually(t, func() bool {
		events, err := manager.GetEvents(ctx, accountID, userID)
		if err != nil {
			return false
		}
		count := 0
		for _, event := range events {
			if event.Activity == activity.AccountTunnelPolicyUpdated {
				count++
			}
		}
		return count == 1
	}, 3*time.Second, 20*time.Millisecond)
}

func TestTunnelLifecycleManagerCancelReplayHasNoSideEffects(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	ctx := context.Background()
	accountID, err := manager.GetAccountIDByUserID(
		ctx,
		auth.UserAuth{UserId: userID},
	)
	require.NoError(t, err)

	now := time.Now().UTC()
	settings, err := manager.Store.GetAccountSettings(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	settings.TunnelPolicy = types.TunnelAccountPolicyStandard
	settings.TunnelProfile = lifecycleAPIProfile(1, "awg2", now.Add(-time.Hour))
	settings.TunnelProfilePending = lifecycleAPIProfile(2, "awg2", now)
	require.NoError(t, manager.Store.SaveAccountSettings(ctx, accountID, settings))

	controller := gomock.NewController(t)
	networkMapController := network_map.NewMockController(controller)
	fanout := make(chan struct{})
	networkMapController.EXPECT().
		UpdateAccountPeers(gomock.Any(), accountID, gomock.Any()).
		DoAndReturn(func(context.Context, string, types.UpdateReason) error {
			close(fanout)
			return nil
		}).
		Times(1)
	manager.networkMapController = networkMapController

	networkBefore, err := manager.Store.GetAccountNetwork(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	target := uint64(2)
	request := managementtunnel.LifecycleRequest{
		Action:         managementtunnel.LifecycleActionCancelPending,
		TargetRevision: &target,
	}
	cancelled, err := manager.UpdateTunnelLifecycle(
		ctx,
		accountID,
		userID,
		request,
	)
	require.NoError(t, err)
	require.True(t, cancelled.Changed)
	require.Nil(t, cancelled.Settings.TunnelProfilePending)
	require.Equal(t, uint64(3), cancelled.Settings.TunnelProfile.Revision)
	select {
	case <-fanout:
	case <-time.After(3 * time.Second):
		t.Fatal("cancel transition did not fan out")
	}

	networkAfterCancel, err := manager.Store.GetAccountNetwork(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	require.Equal(t, networkBefore.Serial+1, networkAfterCancel.Serial)
	afterCancel := cancelled.Settings.Copy()

	replayed, err := manager.UpdateTunnelLifecycle(
		ctx,
		accountID,
		userID,
		request,
	)
	require.NoError(t, err)
	require.False(t, replayed.Changed)
	require.Equal(t, afterCancel, replayed.Settings)
	networkAfterReplay, err := manager.Store.GetAccountNetwork(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	require.Equal(t, networkAfterCancel.Serial, networkAfterReplay.Serial)

	require.Eventually(t, func() bool {
		events, err := manager.GetEvents(ctx, accountID, userID)
		if err != nil {
			return false
		}
		count := 0
		for _, event := range events {
			if event.Activity == activity.AccountTunnelPolicyUpdated {
				count++
			}
		}
		return count == 1
	}, 3*time.Second, 20*time.Millisecond)
}

func TestPostgresqlTunnelLifecycleConcurrentActionsAreIdempotent(t *testing.T) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.PostgresStoreEngine))
	now := time.Now().UTC()
	tests := []postgresqlConcurrentLifecycleCase{
		{
			name: "stage",
			request: managementtunnel.LifecycleRequest{
				Action:          managementtunnel.LifecycleActionStage,
				ProtocolVersion: "awg3",
			},
			prepare: func(settings *types.Settings) {
				resetConcurrentLifecycleSettings(settings)
			},
			assert: func(t *testing.T, settings *types.Settings) {
				require.Nil(t, settings.TunnelProfile)
				require.NotNil(t, settings.TunnelProfilePending)
				require.Equal(t, uint64(1), settings.TunnelProfilePending.Revision)
				require.Equal(t, "awg3", settings.TunnelProfilePending.ProtocolVersion)
				require.Len(t, settings.TunnelProfilePending.HeaderProtectionKey, 32)
				require.Nil(t, settings.TunnelProfilePrevious)
			},
		},
		{
			name: "activate",
			request: managementtunnel.LifecycleRequest{
				Action:         managementtunnel.LifecycleActionActivate,
				TargetRevision: uint64Pointer(2),
			},
			prepare: func(settings *types.Settings) {
				resetConcurrentLifecycleSettings(settings)
				settings.TunnelProfile = concurrentLifecycleProfile(1, 0x11, now)
				settings.TunnelProfilePending = concurrentLifecycleProfile(2, 0x22, now)
			},
			assert: func(t *testing.T, settings *types.Settings) {
				requireConcurrentLifecycleProfile(t, settings.TunnelProfile, 2, 0x22)
				require.Nil(t, settings.TunnelProfilePending)
				requireConcurrentLifecycleProfile(t, settings.TunnelProfilePrevious, 1, 0x11)
			},
		},
		{
			name: "cancel pending",
			request: managementtunnel.LifecycleRequest{
				Action:         managementtunnel.LifecycleActionCancelPending,
				TargetRevision: uint64Pointer(2),
			},
			prepare: func(settings *types.Settings) {
				resetConcurrentLifecycleSettings(settings)
				settings.TunnelProfile = concurrentLifecycleProfile(1, 0x31, now)
				settings.TunnelProfilePending = concurrentLifecycleProfile(2, 0x32, now)
			},
			assert: func(t *testing.T, settings *types.Settings) {
				requireConcurrentLifecycleProfile(t, settings.TunnelProfile, 3, 0x31)
				require.Nil(t, settings.TunnelProfilePending)
				require.Nil(t, settings.TunnelProfilePrevious)
			},
		},
		{
			name: "rollback",
			request: managementtunnel.LifecycleRequest{
				Action:         managementtunnel.LifecycleActionRollback,
				TargetRevision: uint64Pointer(1),
			},
			prepare: func(settings *types.Settings) {
				resetConcurrentLifecycleSettings(settings)
				settings.TunnelProfile = concurrentLifecycleProfile(2, 0x42, now)
				settings.TunnelProfilePrevious = concurrentLifecycleProfile(1, 0x41, now)
				settings.TunnelProfileGraceUntil = now.Add(time.Hour)
			},
			assert: func(t *testing.T, settings *types.Settings) {
				requireConcurrentLifecycleProfile(t, settings.TunnelProfile, 2, 0x42)
				requireConcurrentLifecycleProfile(t, settings.TunnelProfilePending, 3, 0x41)
				requireConcurrentLifecycleProfile(t, settings.TunnelProfilePrevious, 1, 0x41)
				require.WithinDuration(
					t,
					now.Add(time.Hour),
					settings.TunnelProfileGraceUntil,
					time.Microsecond,
				)
			},
		},
		{
			name: "set policy",
			request: managementtunnel.LifecycleRequest{
				Action: managementtunnel.LifecycleActionSetPolicy,
				Policy: types.TunnelAccountPolicyPreferAWG,
			},
			prepare: func(settings *types.Settings) {
				resetConcurrentLifecycleSettings(settings)
				settings.TunnelProfile = concurrentLifecycleProfile(1, 0x51, now)
			},
			assert: func(t *testing.T, settings *types.Settings) {
				require.Equal(t, types.TunnelAccountPolicyPreferAWG, settings.TunnelPolicy)
				requireConcurrentLifecycleProfile(t, settings.TunnelProfile, 1, 0x51)
				require.Nil(t, settings.TunnelProfilePending)
				require.Nil(t, settings.TunnelProfilePrevious)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runPostgresqlConcurrentLifecycleCase(t, test)
		})
	}
}

type postgresqlConcurrentLifecycleCase struct {
	name    string
	request managementtunnel.LifecycleRequest
	prepare func(*types.Settings)
	assert  func(*testing.T, *types.Settings)
}

type concurrentLifecycleOutcome struct {
	result *managementtunnel.LifecycleResult
	err    error
}

func runPostgresqlConcurrentLifecycleCase(
	t *testing.T,
	test postgresqlConcurrentLifecycleCase,
) {
	t.Helper()
	manager, _, err := createManager(t)
	require.NoError(t, err)
	encryptionKey, err := crypt.GenerateKey()
	require.NoError(t, err)
	fieldEncrypt, err := crypt.NewFieldEncrypt(encryptionKey)
	require.NoError(t, err)
	manager.Store.SetFieldEncrypt(fieldEncrypt)
	ctx := context.Background()
	accountID, err := manager.GetAccountIDByUserID(
		ctx,
		auth.UserAuth{UserId: userID},
	)
	require.NoError(t, err)
	settings, err := manager.Store.GetAccountSettings(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	test.prepare(settings)
	require.NoError(t, manager.Store.SaveAccountSettings(ctx, accountID, settings))

	networkBefore, err := manager.Store.GetAccountNetwork(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	eventSaved := make(chan error, 2)
	manager.eventStore = &lifecycleContextEventStore{
		Store: manager.eventStore,
		saved: eventSaved,
	}
	controller := gomock.NewController(t)
	networkMapController := network_map.NewMockController(controller)
	fanout := make(chan struct{})
	networkMapController.EXPECT().
		UpdateAccountPeers(gomock.Any(), accountID, gomock.Any()).
		DoAndReturn(func(context.Context, string, types.UpdateReason) error {
			close(fanout)
			return nil
		}).
		Times(1)
	manager.networkMapController = networkMapController

	start := make(chan struct{})
	outcomes := make(chan concurrentLifecycleOutcome, 2)
	for range 2 {
		go func() {
			<-start
			result, err := manager.UpdateTunnelLifecycle(
				ctx,
				accountID,
				userID,
				test.request,
			)
			outcomes <- concurrentLifecycleOutcome{result: result, err: err}
		}()
	}
	close(start)

	results := make([]*managementtunnel.LifecycleResult, 0, 2)
	changed := 0
	for range 2 {
		outcome := <-outcomes
		require.NoError(t, outcome.err)
		require.NotNil(t, outcome.result)
		results = append(results, outcome.result)
		if outcome.result.Changed {
			changed++
		}
	}
	require.Equal(t, 1, changed)
	select {
	case <-fanout:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent lifecycle transition did not fan out")
	}
	select {
	case err := <-eventSaved:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent lifecycle transition did not store an event")
	}
	select {
	case <-eventSaved:
		t.Fatal("concurrent lifecycle transition stored duplicate events")
	case <-time.After(100 * time.Millisecond):
	}

	finalSettings, err := manager.Store.GetAccountSettings(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	for _, result := range results {
		require.Equal(t, finalSettings.TunnelPolicy, result.Settings.TunnelPolicy)
		requireSameConcurrentLifecycleProfile(
			t,
			finalSettings.TunnelProfile,
			result.Settings.TunnelProfile,
		)
		requireSameConcurrentLifecycleProfile(
			t,
			finalSettings.TunnelProfilePending,
			result.Settings.TunnelProfilePending,
		)
		requireSameConcurrentLifecycleProfile(
			t,
			finalSettings.TunnelProfilePrevious,
			result.Settings.TunnelProfilePrevious,
		)
	}
	test.assert(t, finalSettings)
	networkAfter, err := manager.Store.GetAccountNetwork(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	require.Equal(t, networkBefore.Serial+1, networkAfter.Serial)
}

func resetConcurrentLifecycleSettings(settings *types.Settings) {
	settings.TunnelPolicy = types.TunnelAccountPolicyStandard
	settings.TunnelProfile = nil
	settings.TunnelProfilePending = nil
	settings.TunnelProfilePrevious = nil
	settings.TunnelProfileGraceUntil = time.Time{}
	settings.TunnelProfileAction = ""
}

func concurrentLifecycleProfile(
	revision uint64,
	marker byte,
	now time.Time,
) *types.TunnelProfile {
	return &types.TunnelProfile{
		ProtocolVersion:     "awg3",
		Revision:            revision,
		Parameters:          []byte(`{"junk_packet_count":4}`),
		HeaderProtectionKey: bytes.Repeat([]byte{marker}, 32),
		UpdatedAt:           now,
	}
}

func requireConcurrentLifecycleProfile(
	t *testing.T,
	profile *types.TunnelProfile,
	revision uint64,
	marker byte,
) {
	t.Helper()
	require.NotNil(t, profile)
	require.Equal(t, "awg3", profile.ProtocolVersion)
	require.Equal(t, revision, profile.Revision)
	require.JSONEq(t, `{"junk_packet_count":4}`, string(profile.Parameters))
	require.Equal(t, bytes.Repeat([]byte{marker}, 32), profile.HeaderProtectionKey)
}

func requireSameConcurrentLifecycleProfile(
	t *testing.T,
	expected,
	actual *types.TunnelProfile,
) {
	t.Helper()
	if expected == nil || actual == nil {
		require.Equal(t, expected, actual)
		return
	}
	require.Equal(t, expected.ProtocolVersion, actual.ProtocolVersion)
	require.Equal(t, expected.Revision, actual.Revision)
	require.JSONEq(t, string(expected.Parameters), string(actual.Parameters))
	require.Equal(t, expected.HeaderProtectionKey, actual.HeaderProtectionKey)
}

func TestPostgresqlTunnelLifecycleUsesPostLockPeerSnapshotAndDecisionTime(
	t *testing.T,
) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.PostgresStoreEngine))
	manager, _, err := createManager(t)
	require.NoError(t, err)
	ctx := context.Background()
	accountID, err := manager.GetAccountIDByUserID(
		ctx,
		auth.UserAuth{UserId: userID},
	)
	require.NoError(t, err)

	staged, err := manager.UpdateTunnelLifecycle(
		ctx,
		accountID,
		userID,
		managementtunnel.LifecycleRequest{
			Action:          managementtunnel.LifecycleActionStage,
			ProtocolVersion: "awg2",
		},
	)
	require.NoError(t, err)
	pending := staged.Settings.TunnelProfilePending
	require.NotNil(t, pending)

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	peer, _, _, _, err := manager.AddPeer(
		ctx,
		accountID,
		"",
		userID,
		&nbpeer.Peer{
			Key: key.PublicKey().String(),
			Meta: nbpeer.PeerSystemMeta{
				Hostname: "post-lock-readiness",
				Capabilities: []int32{
					nbpeer.PeerCapabilityHybridAmneziaWG2,
				},
			},
		},
		false,
	)
	require.NoError(t, err)

	decisionTime := pending.UpdatedAt.Add(9 * time.Minute)
	locked := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- manager.Store.ExecuteInTransaction(
			ctx,
			func(transaction store.Store) error {
				if _, err := transaction.GetAccountSettings(
					ctx,
					store.LockingStrengthUpdate,
					accountID,
				); err != nil {
					return err
				}
				close(locked)
				<-release
				storedPeer, err := transaction.GetPeerByID(
					ctx,
					store.LockingStrengthUpdate,
					accountID,
					peer.ID,
				)
				if err != nil {
					return err
				}
				storedPeer.Status.LastSeen = decisionTime.Add(-11 * time.Minute)
				storedPeer.Meta.TunnelRuntime = nbpeer.TunnelRuntimeMeta{
					ProtocolVersion: "awg2",
					ProfileRevision: pending.Revision,
					AdapterRevision: managementtunnel.HybridAWG2AdapterRevision,
					Ready:           false,
					UpdatedAt:       decisionTime,
				}
				return transaction.SavePeer(ctx, accountID, storedPeer)
			},
		)
	}()
	<-locked

	target := pending.Revision
	activationDone := make(chan error, 1)
	clockCalled := make(chan struct{}, 1)
	go func() {
		_, err := manager.updateTunnelLifecycleWithClock(
			ctx,
			accountID,
			managementtunnel.LifecycleRequest{
				Action:         managementtunnel.LifecycleActionActivate,
				TargetRevision: &target,
			},
			func() time.Time {
				clockCalled <- struct{}{}
				return decisionTime
			},
		)
		activationDone <- err
	}()
	select {
	case <-clockCalled:
		t.Fatal("decision clock called before the settings lock was released")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-holderDone)

	err = <-activationDone
	var lifecycleErr *managementtunnel.LifecycleError
	require.ErrorAs(t, err, &lifecycleErr)
	require.Equal(t, managementtunnel.LifecycleErrorNotReady, lifecycleErr.Code)
	select {
	case <-clockCalled:
	default:
		t.Fatal("decision clock was not called after reading the peer snapshot")
	}

	readiness, err := manager.getTunnelLifecycleWithClock(
		ctx,
		accountID,
		func() time.Time { return decisionTime },
	)
	require.NoError(t, err)
	require.Equal(t, 1, readiness.Readiness.Eligible)
	require.Equal(t, 1, readiness.Readiness.Waiting)
	require.Equal(t, decisionTime, readiness.Readiness.ObservedAt)
}

func TestTunnelLifecyclePostCommitUsesUncancelledContext(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	eventSaved := make(chan error, 2)
	manager.eventStore = &lifecycleContextEventStore{
		Store: manager.eventStore,
		saved: eventSaved,
	}
	controller := gomock.NewController(t)
	networkMapController := network_map.NewMockController(controller)
	fanout := make(chan error, 1)
	networkMapController.EXPECT().
		UpdateAccountPeers(gomock.Any(), "account", gomock.Any()).
		DoAndReturn(func(ctx context.Context, _ string, _ types.UpdateReason) error {
			fanout <- ctx.Err()
			return nil
		}).
		Times(1)
	manager.networkMapController = networkMapController

	manager.publishTunnelLifecycleChange(
		ctx,
		"account",
		userID,
		managementtunnel.LifecycleRequest{
			Action: managementtunnel.LifecycleActionSetPolicy,
		},
		&types.Settings{},
	)
	require.NoError(t, <-eventSaved)
	require.NoError(t, <-fanout)
	select {
	case <-eventSaved:
		t.Fatal("lifecycle event was saved more than once")
	case <-time.After(100 * time.Millisecond):
	}
}

type lifecycleContextEventStore struct {
	activity.Store
	saved chan error
}

func (s *lifecycleContextEventStore) Save(
	ctx context.Context,
	event *activity.Event,
) (*activity.Event, error) {
	s.saved <- ctx.Err()
	return s.Store.Save(ctx, event)
}

func TestTunnelLifecycleManagerAuthorizationMatrix(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	ctx := context.Background()
	accountID, err := manager.GetAccountIDByUserID(
		ctx,
		auth.UserAuth{UserId: userID},
	)
	require.NoError(t, err)

	auditor := types.NewUser(
		"auditor",
		types.UserRoleAuditor,
		false,
		false,
		"",
		nil,
		types.UserIssuedAPI,
		"",
		"",
	)
	auditor.AccountID = accountID
	regular := types.NewRegularUser("regular", "", "")
	regular.AccountID = accountID
	admin := types.NewAdminUser("admin")
	admin.AccountID = accountID
	require.NoError(t, manager.Store.SaveUsers(
		ctx,
		[]*types.User{auditor, regular, admin},
	))

	_, err = manager.GetTunnelLifecycle(ctx, accountID, auditor.Id)
	require.NoError(t, err)
	requests := []managementtunnel.LifecycleRequest{
		{
			Action:          managementtunnel.LifecycleActionStage,
			ProtocolVersion: "awg2",
		},
		{
			Action:         managementtunnel.LifecycleActionActivate,
			TargetRevision: uint64Pointer(1),
		},
		{
			Action:         managementtunnel.LifecycleActionCancelPending,
			TargetRevision: uint64Pointer(1),
		},
		{
			Action:         managementtunnel.LifecycleActionRollback,
			TargetRevision: uint64Pointer(1),
		},
		{
			Action: managementtunnel.LifecycleActionSetPolicy,
			Policy: types.TunnelAccountPolicyStandard,
		},
	}
	for _, request := range requests {
		_, err = manager.UpdateTunnelLifecycle(
			ctx,
			accountID,
			auditor.Id,
			request,
		)
		requirePermissionDenied(t, err)
	}
	_, err = manager.GetTunnelLifecycle(ctx, accountID, regular.Id)
	require.Error(t, err)
	for _, request := range requests {
		_, err = manager.UpdateTunnelLifecycle(
			ctx,
			accountID,
			regular.Id,
			request,
		)
		requirePermissionDenied(t, err)
	}
	for _, request := range requests {
		_, err = manager.UpdateTunnelLifecycle(
			ctx,
			accountID,
			admin.Id,
			request,
		)
		if statusErr, ok := sharedstatus.FromError(err); ok && err != nil {
			require.NotEqual(t, sharedstatus.PermissionDenied, statusErr.Type())
		}
	}
	_, err = manager.GetTunnelLifecycle(ctx, "other-account", userID)
	require.Error(t, err)
}

func TestTunnelLifecycleManagerOriginalReplayHasNoSideEffects(t *testing.T) {
	now := time.Now().UTC()
	one := uint64(1)
	two := uint64(2)
	zero := uint64(0)
	tests := []struct {
		name     string
		settings *types.Settings
		request  managementtunnel.LifecycleRequest
	}{
		{
			name: "stage",
			settings: &types.Settings{
				TunnelProfile:        lifecycleAPIProfile(1, "awg2", now),
				TunnelProfilePending: lifecycleAPIProfile(2, "awg2", now),
			},
			request: managementtunnel.LifecycleRequest{
				Action:                  managementtunnel.LifecycleActionStage,
				ProtocolVersion:         "awg2",
				ExpectedActiveRevision:  &one,
				ExpectedPendingRevision: &zero,
			},
		},
		{
			name: "activate",
			settings: &types.Settings{
				TunnelProfile: lifecycleAPIProfile(2, "awg2", now),
			},
			request: managementtunnel.LifecycleRequest{
				Action:                  managementtunnel.LifecycleActionActivate,
				TargetRevision:          &two,
				ExpectedActiveRevision:  &one,
				ExpectedPendingRevision: &two,
			},
		},
		{
			name: "cancel",
			settings: &types.Settings{
				TunnelPolicy:  types.TunnelAccountPolicyStandard,
				TunnelProfile: lifecycleAPIProfile(3, "awg2", now),
			},
			request: managementtunnel.LifecycleRequest{
				Action:                  managementtunnel.LifecycleActionCancelPending,
				TargetRevision:          &two,
				Policy:                  types.TunnelAccountPolicyStandard,
				ExpectedActiveRevision:  &one,
				ExpectedPendingRevision: &two,
			},
		},
		{
			name: "rollback",
			settings: &types.Settings{
				TunnelProfile:           lifecycleAPIProfile(2, "awg2", now),
				TunnelProfilePending:    lifecycleAPIProfile(3, "awg2", now),
				TunnelProfilePrevious:   lifecycleAPIProfile(1, "awg2", now),
				TunnelProfileGraceUntil: now.Add(time.Hour),
			},
			request: managementtunnel.LifecycleRequest{
				Action:                  managementtunnel.LifecycleActionRollback,
				TargetRevision:          &one,
				ExpectedActiveRevision:  &two,
				ExpectedPendingRevision: &zero,
			},
		},
		{
			name: "set policy",
			settings: &types.Settings{
				TunnelPolicy:  types.TunnelAccountPolicyPreferAWG,
				TunnelProfile: lifecycleAPIProfile(2, "awg2", now),
			},
			request: managementtunnel.LifecycleRequest{
				Action:                 managementtunnel.LifecycleActionSetPolicy,
				Policy:                 types.TunnelAccountPolicyPreferAWG,
				ExpectedActiveRevision: &one,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager, _, err := createManager(t)
			require.NoError(t, err)
			ctx := context.Background()
			accountID, err := manager.GetAccountIDByUserID(
				ctx,
				auth.UserAuth{UserId: userID},
			)
			require.NoError(t, err)
			current, err := manager.Store.GetAccountSettings(
				ctx,
				store.LockingStrengthNone,
				accountID,
			)
			require.NoError(t, err)
			current.TunnelPolicy = test.settings.TunnelPolicy
			current.TunnelProfile = test.settings.TunnelProfile
			current.TunnelProfilePending = test.settings.TunnelProfilePending
			current.TunnelProfilePrevious = test.settings.TunnelProfilePrevious
			current.TunnelProfileGraceUntil = test.settings.TunnelProfileGraceUntil
			require.NoError(t, manager.Store.SaveAccountSettings(
				ctx,
				accountID,
				current,
			))
			networkBefore, err := manager.Store.GetAccountNetwork(
				ctx,
				store.LockingStrengthNone,
				accountID,
			)
			require.NoError(t, err)

			result, err := manager.UpdateTunnelLifecycle(
				ctx,
				accountID,
				userID,
				test.request,
			)
			require.NoError(t, err)
			require.False(t, result.Changed)
			networkAfter, err := manager.Store.GetAccountNetwork(
				ctx,
				store.LockingStrengthNone,
				accountID,
			)
			require.NoError(t, err)
			require.Equal(t, networkBefore.Serial, networkAfter.Serial)
			time.Sleep(25 * time.Millisecond)
			events, err := manager.GetEvents(ctx, accountID, userID)
			require.NoError(t, err)
			for _, event := range events {
				require.NotEqual(t, activity.AccountTunnelPolicyUpdated, event.Activity)
			}
		})
	}
}

func lifecycleAPIProfile(
	revision uint64,
	protocol string,
	now time.Time,
) *types.TunnelProfile {
	return &types.TunnelProfile{
		ProtocolVersion: protocol,
		Revision:        revision,
		Parameters:      []byte(`{"junk_packet_count":4}`),
		UpdatedAt:       now,
	}
}

func uint64Pointer(value uint64) *uint64 {
	return &value
}

func requirePermissionDenied(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	statusErr, ok := sharedstatus.FromError(err)
	require.True(t, ok)
	require.Equal(t, sharedstatus.PermissionDenied, statusErr.Type())
}
