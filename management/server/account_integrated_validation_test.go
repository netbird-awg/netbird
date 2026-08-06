package server

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestAccountManager_EDRPeerChangesRevalidateWithoutExpiringLogin(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	account, err := createAccount(manager, "edr-account", "owner", "")
	require.NoError(t, err)
	account.Peers["compliant"] = &nbpeer.Peer{
		ID:       "compliant",
		Key:      "compliant-key",
		DNSLabel: "compliant",
		IP:       netip.MustParseAddr("100.64.0.10"),
		IPv6:     netip.MustParseAddr("fd00::10"),
		UserID:   "owner",
		Status:   &nbpeer.PeerStatus{},
	}
	account.Peers["invalid-sso"] = &nbpeer.Peer{
		ID:       "invalid-sso",
		Key:      "invalid-sso-key",
		DNSLabel: "invalid-sso",
		IP:       netip.MustParseAddr("100.64.0.11"),
		IPv6:     netip.MustParseAddr("fd00::11"),
		UserID:   "owner",
		Status:   &nbpeer.PeerStatus{},
	}
	account.Peers["invalid-setup"] = &nbpeer.Peer{
		ID:       "invalid-setup",
		Key:      "invalid-setup-key",
		DNSLabel: "invalid-setup",
		IP:       netip.MustParseAddr("100.64.0.12"),
		IPv6:     netip.MustParseAddr("fd00::12"),
		Status:   &nbpeer.PeerStatus{},
	}
	require.NoError(t, manager.Store.SaveAccount(context.Background(), account))

	manager.integratedPeerValidator = MockIntegratedValidator{
		GetValidatedPeersFunc: func(
			context.Context,
			string,
			[]*types.Group,
			[]*nbpeer.Peer,
			*types.ExtraSettings,
		) (map[string]struct{}, error) {
			return map[string]struct{}{"compliant": {}}, nil
		},
	}

	ctrl := gomock.NewController(t)
	networkMapController := network_map.NewMockController(ctrl)
	networkMapController.EXPECT().
		OnPeersUpdated(
			gomock.Any(),
			account.Id,
			[]string{"invalid-setup", "invalid-sso"},
			gomock.Any(),
		).
		Return(nil)
	networkMapController.EXPECT().
		DisconnectPeers(
			gomock.Any(),
			account.Id,
			[]string{"invalid-setup", "invalid-sso"},
		)
	manager.networkMapController = networkMapController

	manager.onPeersInvalidated(
		context.Background(),
		account.Id,
		[]string{"invalid-sso", "compliant", "invalid-setup", "invalid-sso"},
	)
	manager.onPeersInvalidated(
		context.Background(),
		account.Id,
		[]string{"invalid-sso", "compliant", "invalid-setup"},
	)

	for _, peerID := range []string{"compliant", "invalid-sso", "invalid-setup"} {
		peer, err := manager.Store.GetPeerByID(
			context.Background(),
			store.LockingStrengthNone,
			account.Id,
			peerID,
		)
		require.NoError(t, err)
		require.False(t, peer.Status.LoginExpired)
		require.Equal(t, peerID != "compliant", peer.Status.RequiresApproval)
	}
}
