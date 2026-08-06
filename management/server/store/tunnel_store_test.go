package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestEnsureAccountTunnelPolicyTimestamps(t *testing.T) {
	accountCreatedAt := time.Date(2026, time.August, 7, 1, 2, 3, 0, time.UTC)
	userCreatedAt := accountCreatedAt.Add(time.Minute)
	account := &types.Account{
		CreatedAt: accountCreatedAt,
		Settings:  &types.Settings{},
		Users: map[string]*types.User{
			"user": {
				CreatedAt: userCreatedAt,
			},
		},
	}

	ensureAccountTunnelPolicyTimestamps(account)

	require.Equal(t, accountCreatedAt, account.Settings.TunnelPolicyUpdatedAt)
	require.Equal(
		t,
		userCreatedAt,
		account.Users["user"].TunnelPolicyUpdatedAt,
	)
}

func TestTunnelStateRoundTrip(t *testing.T) {
	ctx := context.Background()
	sqlStore, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	now := time.Now().UTC().Truncate(time.Millisecond)
	account := newAccountWithId(ctx, "tunnel-account", "tunnel-user", "")
	account.Settings.TunnelPolicy = types.TunnelAccountPolicyPreferAWG
	account.Settings.TunnelPolicyUpdatedAt = now
	account.Settings.TunnelProfile = &types.TunnelProfile{
		ProtocolVersion: "awg2",
		Revision:        9,
		Parameters: json.RawMessage(
			`{"h1":"101","h2":"102","h3":"103","h4":"104"}`,
		),
		UpdatedAt: now,
	}
	user := account.Users["tunnel-user"]
	user.TunnelPolicy = types.TunnelUserPolicyPreferAWG
	user.TunnelPolicyUpdatedAt = now
	account.Peers["tunnel-peer"] = &nbpeer.Peer{
		ID:        "tunnel-peer",
		AccountID: account.Id,
		UserID:    user.Id,
		Key:       "tunnel-peer-key",
		IP:        netip.MustParseAddr("100.64.0.10"),
		Meta: nbpeer.PeerSystemMeta{
			TunnelRuntime: nbpeer.TunnelRuntimeMeta{
				ProtocolVersion:   "awg2",
				ProfileRevision:   9,
				AdapterRevision:   "adapter",
				Ready:             true,
				UpdatedAt:         now,
				LastReadyProtocol: "awg2",
				LastReadyRevision: 9,
				LastReadyAt:       now,
			},
		},
	}

	require.NoError(t, sqlStore.SaveAccount(ctx, account))

	stored, err := sqlStore.GetAccount(ctx, account.Id)
	require.NoError(t, err)
	require.Equal(t, account.Settings.TunnelPolicy, stored.Settings.TunnelPolicy)
	require.Equal(t, account.Settings.TunnelProfile, stored.Settings.TunnelProfile)
	require.Equal(t, user.TunnelPolicy, stored.Users[user.Id].TunnelPolicy)
	require.Equal(
		t,
		account.Peers["tunnel-peer"].Meta.TunnelRuntime,
		stored.Peers["tunnel-peer"].Meta.TunnelRuntime,
	)
}
