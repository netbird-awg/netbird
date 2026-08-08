package server

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	clienttunnel "github.com/netbirdio/netbird/client/iface/tunnel"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	managementtunnel "github.com/netbirdio/netbird/management/server/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/util/crypt"
)

func TestUpdateAccountSettingsActivatesAcknowledgedAWG3Profile(t *testing.T) {
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
	settings.TunnelPolicy = types.TunnelAccountPolicyPreferAWG
	settings.TunnelProfile = &types.TunnelProfile{
		ProtocolVersion: clienttunnel.ProtocolAmneziaWG3,
		Revision:        1,
		Parameters:      json.RawMessage(`{}`),
	}

	staged, err := manager.UpdateAccountSettings(
		ctx,
		accountID,
		userID,
		settings,
	)
	require.NoError(t, err)
	require.Nil(t, staged.TunnelProfile)
	require.NotNil(t, staged.TunnelProfilePending)
	require.Len(t, staged.TunnelProfilePending.HeaderProtectionKey, 32)

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	now := time.Now().UTC()
	_, _, _, _, err = manager.AddPeer(
		ctx,
		accountID,
		"",
		userID,
		&nbpeer.Peer{
			Key: key.PublicKey().String(),
			Meta: nbpeer.PeerSystemMeta{
				Hostname: "awg3-ready",
				Capabilities: []int32{
					nbpeer.PeerCapabilityHybridAmneziaWG2,
					nbpeer.PeerCapabilityHybridAmneziaWG3,
				},
				TunnelRuntime: nbpeer.TunnelRuntimeMeta{
					ProtocolVersion: clienttunnel.ProtocolAmneziaWG3,
					ProfileRevision: 1,
					AdapterRevision: managementtunnel.
						HybridAWG3AdapterRevision,
					Ready:     true,
					UpdatedAt: now,
				},
			},
		},
		false,
	)
	require.NoError(t, err)
	staleKey, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	stalePeer, _, _, _, err := manager.AddPeer(
		ctx,
		accountID,
		"",
		userID,
		&nbpeer.Peer{
			Key: staleKey.PublicKey().String(),
			Meta: nbpeer.PeerSystemMeta{
				Hostname: "awg3-stale",
				Capabilities: []int32{
					nbpeer.PeerCapabilityHybridAmneziaWG2,
					nbpeer.PeerCapabilityHybridAmneziaWG3,
				},
			},
		},
		false,
	)
	require.NoError(t, err)
	require.NoError(t, manager.Store.SavePeerStatus(
		ctx,
		accountID,
		stalePeer.ID,
		nbpeer.PeerStatus{
			LastSeen:  now.Add(-time.Hour),
			Connected: true,
		},
	))

	activation := staged.Copy()
	activation.TunnelProfileAction = types.TunnelProfileActionActivate
	activated, err := manager.UpdateAccountSettings(
		ctx,
		accountID,
		userID,
		activation,
	)
	require.NoError(t, err)
	require.NotNil(t, activated.TunnelProfile)
	require.Equal(t, uint64(1), activated.TunnelProfile.Revision)
	require.Nil(t, activated.TunnelProfilePending)
	require.True(
		t,
		bytes.Equal(
			staged.TunnelProfilePending.HeaderProtectionKey,
			activated.TunnelProfile.HeaderProtectionKey,
		),
	)
}

func TestUpdateAccountSettingsActivationIncludesEligibleUnreadyPeers(
	t *testing.T,
) {
	tests := []struct {
		name             string
		staleLastSeen    bool
		runtimeUpdatedAt bool
	}{
		{name: "recent activity"},
		{
			name:             "runtime report since pending",
			staleLastSeen:    true,
			runtimeUpdatedAt: true,
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
			settings, err := manager.Store.GetAccountSettings(
				ctx,
				store.LockingStrengthNone,
				accountID,
			)
			require.NoError(t, err)
			now := time.Now().UTC()
			settings.TunnelPolicy = types.TunnelAccountPolicyPreferAWG
			settings.TunnelProfile = accountTestTunnelProfile(1, now.Add(-time.Hour))
			settings.TunnelProfilePending = accountTestTunnelProfile(
				2,
				now.Add(-time.Minute),
			)
			require.NoError(t, manager.Store.SaveAccountSettings(
				ctx,
				accountID,
				settings,
			))

			key, err := wgtypes.GenerateKey()
			require.NoError(t, err)
			runtimeUpdatedAt := time.Time{}
			if test.runtimeUpdatedAt {
				runtimeUpdatedAt = now
			}
			peer, _, _, _, err := manager.AddPeer(
				ctx,
				accountID,
				"",
				userID,
				&nbpeer.Peer{
					Key: key.PublicKey().String(),
					Meta: nbpeer.PeerSystemMeta{
						Hostname: "awg2-unready",
						Capabilities: []int32{
							nbpeer.PeerCapabilityHybridAmneziaWG2,
						},
						TunnelRuntime: nbpeer.TunnelRuntimeMeta{
							ProtocolVersion: clienttunnel.ProtocolAmneziaWG2,
							ProfileRevision: 2,
							AdapterRevision: managementtunnel.
								HybridAWG2AdapterRevision,
							UpdatedAt: runtimeUpdatedAt,
						},
					},
				},
				false,
			)
			require.NoError(t, err)
			if test.staleLastSeen {
				require.NoError(t, manager.Store.SavePeerStatus(
					ctx,
					accountID,
					peer.ID,
					nbpeer.PeerStatus{LastSeen: now.Add(-time.Hour)},
				))
			}

			activation := settings.Copy()
			activation.TunnelProfileAction = types.TunnelProfileActionActivate
			_, err = manager.UpdateAccountSettings(
				ctx,
				accountID,
				userID,
				activation,
			)
			require.Error(t, err)
		})
	}
}

func TestUpdateAccountSettingsActivationIgnoresIneligiblePeers(t *testing.T) {
	for _, test := range []struct {
		name    string
		addPeer bool
		hybrid  bool
		dormant bool
	}{
		{name: "zero peers"},
		{name: "all dormant", addPeer: true, hybrid: true, dormant: true},
		{name: "all legacy", addPeer: true},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			now := time.Now().UTC()
			settings.TunnelPolicy = types.TunnelAccountPolicyPreferAWG
			settings.TunnelProfile = accountTestTunnelProfile(1, now.Add(-time.Hour))
			settings.TunnelProfilePending = accountTestTunnelProfile(
				2,
				now.Add(-time.Minute),
			)
			require.NoError(t, manager.Store.SaveAccountSettings(
				ctx,
				accountID,
				settings,
			))

			if test.addPeer {
				key, err := wgtypes.GenerateKey()
				require.NoError(t, err)
				capabilities := []int32(nil)
				if test.hybrid {
					capabilities = []int32{
						nbpeer.PeerCapabilityHybridAmneziaWG2,
					}
				}
				peer, _, _, _, err := manager.AddPeer(
					ctx,
					accountID,
					"",
					userID,
					&nbpeer.Peer{
						Key: key.PublicKey().String(),
						Meta: nbpeer.PeerSystemMeta{
							Hostname:     "activation-ineligible",
							Capabilities: capabilities,
						},
					},
					false,
				)
				require.NoError(t, err)
				if test.dormant {
					require.NoError(t, manager.Store.SavePeerStatus(
						ctx,
						accountID,
						peer.ID,
						nbpeer.PeerStatus{
							LastSeen:  now.Add(-time.Hour),
							Connected: true,
						},
					))
				}
			}

			activation := settings.Copy()
			activation.TunnelProfileAction = types.TunnelProfileActionActivate
			activated, err := manager.UpdateAccountSettings(
				ctx,
				accountID,
				userID,
				activation,
			)
			require.NoError(t, err)
			require.Equal(t, uint64(2), activated.TunnelProfile.Revision)
			require.Nil(t, activated.TunnelProfilePending)
		})
	}
}

func TestUpdateAccountSettingsCancelPendingIncrementsSerialOnce(t *testing.T) {
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
	now := time.Now().UTC()
	settings.TunnelPolicy = types.TunnelAccountPolicyPreferAWG
	settings.TunnelProfile = accountTestTunnelProfile(7, now.Add(-time.Hour))
	settings.TunnelProfilePending = accountTestTunnelProfile(
		8,
		now.Add(-time.Minute),
	)
	require.NoError(t, manager.Store.SaveAccountSettings(ctx, accountID, settings))
	networkBefore, err := manager.Store.GetAccountNetwork(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)

	cancel := settings.Copy()
	cancel.TunnelProfileAction = types.TunnelProfileActionCancelPending
	cancelled, err := manager.UpdateAccountSettings(
		ctx,
		accountID,
		userID,
		cancel,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(9), cancelled.TunnelProfile.Revision)
	require.Nil(t, cancelled.TunnelProfilePending)
	networkAfterCancel, err := manager.Store.GetAccountNetwork(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	require.Equal(t, networkBefore.Serial+1, networkAfterCancel.Serial)

	repeat := cancelled.Copy()
	repeat.TunnelProfileAction = types.TunnelProfileActionCancelPending
	repeated, err := manager.UpdateAccountSettings(
		ctx,
		accountID,
		userID,
		repeat,
	)
	require.NoError(t, err)
	require.Equal(t, uint64(9), repeated.TunnelProfile.Revision)
	networkAfterRepeat, err := manager.Store.GetAccountNetwork(
		ctx,
		store.LockingStrengthNone,
		accountID,
	)
	require.NoError(t, err)
	require.Equal(t, networkAfterCancel.Serial, networkAfterRepeat.Serial)
}

func TestPostgresql_UpdateAccountSettingsConcurrentTunnelLifecycle(
	t *testing.T,
) {
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.PostgresStoreEngine))
	encryptionKey, err := crypt.GenerateKey()
	require.NoError(t, err)
	fieldEncrypt, err := crypt.NewFieldEncrypt(encryptionKey)
	require.NoError(t, err)
	manager, _, err := createManager(t)
	require.NoError(t, err)
	manager.Store.SetFieldEncrypt(fieldEncrypt)
	ctx := context.Background()
	accountID, err := manager.GetAccountIDByUserID(
		ctx,
		auth.UserAuth{UserId: userID},
	)
	require.NoError(t, err)

	for _, test := range []struct {
		name        string
		actions     [2]types.TunnelProfileAction
		assertFinal func(
			t *testing.T,
			settings *types.Settings,
			results map[types.TunnelProfileAction][]error,
		)
	}{
		{
			name: "cancel and cancel",
			actions: [2]types.TunnelProfileAction{
				types.TunnelProfileActionCancelPending,
				types.TunnelProfileActionCancelPending,
			},
			assertFinal: func(
				t *testing.T,
				settings *types.Settings,
				results map[types.TunnelProfileAction][]error,
			) {
				require.Len(t, results[types.TunnelProfileActionCancelPending], 2)
				for _, err := range results[types.TunnelProfileActionCancelPending] {
					require.NoError(t, err)
				}
				require.Equal(t, uint64(9), settings.TunnelProfile.Revision)
				require.Nil(t, settings.TunnelProfilePrevious)
			},
		},
		{
			name: "cancel and activate",
			actions: [2]types.TunnelProfileAction{
				types.TunnelProfileActionCancelPending,
				types.TunnelProfileActionActivate,
			},
			assertFinal: func(
				t *testing.T,
				settings *types.Settings,
				results map[types.TunnelProfileAction][]error,
			) {
				require.Len(t, results[types.TunnelProfileActionCancelPending], 1)
				require.Len(t, results[types.TunnelProfileActionActivate], 1)
				require.NoError(
					t,
					results[types.TunnelProfileActionCancelPending][0],
				)
				activateErr := results[types.TunnelProfileActionActivate][0]
				if activateErr != nil {
					require.Equal(t, uint64(9), settings.TunnelProfile.Revision)
					require.Nil(t, settings.TunnelProfilePrevious)
					return
				}
				require.Equal(t, uint64(8), settings.TunnelProfile.Revision)
				require.NotNil(t, settings.TunnelProfilePrevious)
				require.Equal(
					t,
					uint64(7),
					settings.TunnelProfilePrevious.Revision,
				)
				require.Equal(
					t,
					settings.TunnelProfile.HeaderProtectionKey,
					settings.TunnelProfilePrevious.HeaderProtectionKey,
				)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			settings, err := manager.Store.GetAccountSettings(
				ctx,
				store.LockingStrengthNone,
				accountID,
			)
			require.NoError(t, err)
			now := time.Now().UTC()
			secret := bytes.Repeat([]byte{0x7b}, 32)
			parameters := json.RawMessage(
				`{"s1":12,"s2":12,"s3":12,"s4":12,` +
					`"h1":"101","h2":"102","h3":"103","h4":"104",` +
					`"content_padding_addition":"1-16"}`,
			)
			settings.TunnelPolicy = types.TunnelAccountPolicyPreferAWG
			settings.TunnelProfile = accountTestTunnelProfile(
				7,
				now.Add(-time.Hour),
			)
			settings.TunnelProfile.ProtocolVersion =
				clienttunnel.ProtocolAmneziaWG3
			settings.TunnelProfile.Parameters = append([]byte(nil), parameters...)
			settings.TunnelProfile.HeaderProtectionKey =
				append([]byte(nil), secret...)
			settings.TunnelProfilePending = accountTestTunnelProfile(
				8,
				now.Add(-time.Minute),
			)
			settings.TunnelProfilePending.ProtocolVersion =
				clienttunnel.ProtocolAmneziaWG3
			settings.TunnelProfilePending.Parameters =
				append([]byte(nil), parameters...)
			settings.TunnelProfilePending.HeaderProtectionKey =
				append([]byte(nil), secret...)
			require.NoError(t, manager.Store.SaveAccountSettings(
				ctx,
				accountID,
				settings,
			))
			networkBefore, err := manager.Store.GetAccountNetwork(
				ctx,
				store.LockingStrengthNone,
				accountID,
			)
			require.NoError(t, err)

			type lifecycleResult struct {
				action types.TunnelProfileAction
				err    error
			}
			start := make(chan struct{})
			resultsChannel := make(chan lifecycleResult, len(test.actions))
			var calls sync.WaitGroup
			for _, action := range test.actions {
				request := settings.Copy()
				request.TunnelProfileAction = action
				calls.Add(1)
				go func() {
					defer calls.Done()
					<-start
					_, err := manager.UpdateAccountSettings(
						ctx,
						accountID,
						userID,
						request,
					)
					resultsChannel <- lifecycleResult{action: action, err: err}
				}()
			}
			close(start)
			calls.Wait()
			close(resultsChannel)

			results := make(map[types.TunnelProfileAction][]error)
			for result := range resultsChannel {
				results[result.action] = append(results[result.action], result.err)
			}
			stored, err := manager.Store.GetAccountSettings(
				ctx,
				store.LockingStrengthNone,
				accountID,
			)
			require.NoError(t, err)
			require.Nil(t, stored.TunnelProfilePending)
			require.Equal(t, secret, stored.TunnelProfile.HeaderProtectionKey)
			require.Equal(
				t,
				settings.TunnelProfile.Parameters,
				stored.TunnelProfile.Parameters,
			)
			test.assertFinal(t, stored, results)

			networkAfter, err := manager.Store.GetAccountNetwork(
				ctx,
				store.LockingStrengthNone,
				accountID,
			)
			require.NoError(t, err)
			require.Equal(t, networkBefore.Serial+1, networkAfter.Serial)
		})
	}
}

func accountTestTunnelProfile(
	revision uint64,
	updatedAt time.Time,
) *types.TunnelProfile {
	return &types.TunnelProfile{
		ProtocolVersion: clienttunnel.ProtocolAmneziaWG2,
		Revision:        revision,
		Parameters: json.RawMessage(
			`{"h1":"101","h2":"102","h3":"103","h4":"104"}`,
		),
		UpdatedAt: updatedAt,
	}
}

func TestTunnelProfileActivationPeerEligibilityUsesRecentPersistedSignals(
	t *testing.T,
) {
	now := time.Now().UTC()
	pending := &types.TunnelProfile{UpdatedAt: now.Add(-time.Minute)}
	tests := []struct {
		name    string
		peer    *nbpeer.Peer
		pending *types.TunnelProfile
		want    bool
	}{
		{
			name: "exact activity cutoff",
			peer: activationTestPeer(
				now.Add(-tunnelProfileActivationActivityWindow),
				time.Time{},
				false,
			),
			want: true,
		},
		{
			name: "before activity cutoff",
			peer: activationTestPeer(
				now.Add(-tunnelProfileActivationActivityWindow-time.Nanosecond),
				time.Time{},
				false,
			),
		},
		{
			name: "future last seen",
			peer: activationTestPeer(
				now.Add(time.Nanosecond),
				time.Time{},
				false,
			),
		},
		{
			name: "stale connected flag",
			peer: activationTestPeer(
				now.Add(-time.Hour),
				time.Time{},
				true,
			),
		},
		{
			name: "runtime at pending update",
			peer: activationTestPeer(
				now.Add(-time.Hour),
				pending.UpdatedAt,
				false,
			),
			want: true,
		},
		{
			name: "runtime before pending update",
			peer: activationTestPeer(
				now.Add(-time.Hour),
				pending.UpdatedAt.Add(-time.Nanosecond),
				false,
			),
		},
		{
			name: "runtime at recent cutoff for old pending",
			peer: activationTestPeer(
				now.Add(-time.Hour),
				now.Add(-tunnelProfileActivationActivityWindow),
				false,
			),
			pending: &types.TunnelProfile{UpdatedAt: now.Add(-time.Hour)},
			want:    true,
		},
		{
			name: "old pending and old unready runtime",
			peer: activationTestPeer(
				now.Add(-time.Hour),
				now.Add(-tunnelProfileActivationActivityWindow-time.Nanosecond),
				false,
			),
			pending: &types.TunnelProfile{UpdatedAt: now.Add(-time.Hour)},
		},
		{
			name: "future runtime update",
			peer: activationTestPeer(
				now.Add(-time.Hour),
				now.Add(time.Nanosecond),
				false,
			),
		},
		{
			name: "zero activity",
			peer: activationTestPeer(time.Time{}, time.Time{}, false),
		},
		{
			name: "nil status",
			peer: func() *nbpeer.Peer {
				peer := activationTestPeer(time.Time{}, time.Time{}, false)
				peer.Status = nil
				return peer
			}(),
		},
		{
			name: "legacy recent peer",
			peer: func() *nbpeer.Peer {
				peer := activationTestPeer(now, time.Time{}, false)
				peer.Meta.Capabilities = nil
				return peer
			}(),
		},
		{
			name: "login expired",
			peer: func() *nbpeer.Peer {
				peer := activationTestPeer(now, now, false)
				peer.Status.LoginExpired = true
				return peer
			}(),
		},
		{
			name: "requires approval",
			peer: func() *nbpeer.Peer {
				peer := activationTestPeer(now, now, false)
				peer.Status.RequiresApproval = true
				return peer
			}(),
		},
		{name: "nil peer"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testPending := test.pending
			if testPending == nil {
				testPending = pending
			}
			got := tunnelProfileActivationPeerEligible(
				test.peer,
				testPending,
				now,
			)
			require.Equal(t, test.want, got)
		})
	}
}

func activationTestPeer(
	lastSeen,
	runtimeUpdatedAt time.Time,
	connected bool,
) *nbpeer.Peer {
	return &nbpeer.Peer{
		Status: &nbpeer.PeerStatus{
			LastSeen:  lastSeen,
			Connected: connected,
		},
		Meta: nbpeer.PeerSystemMeta{
			Capabilities: []int32{nbpeer.PeerCapabilityHybridAmneziaWG2},
			TunnelRuntime: nbpeer.TunnelRuntimeMeta{
				UpdatedAt: runtimeUpdatedAt,
			},
		},
	}
}
