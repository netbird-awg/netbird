package server

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

func TestAdminPasswordResetRequiresChangeAndInvalidatesAccess(t *testing.T) {
	manager, _, err := createManagerWithEmbeddedIdP(t)
	require.NoError(t, err)
	ctx := t.Context()
	ownerID := "owner"
	account, err := manager.GetOrCreateAccountByUser(ctx, auth.UserAuth{
		UserId: ownerID,
		Email:  "owner@example.org",
		Name:   "Owner",
	})
	require.NoError(t, err)

	created, err := manager.CreateUser(ctx, account.Id, ownerID, &types.UserInfo{
		Email:      "reset-user@example.org",
		Name:       "Reset User",
		Role:       string(types.UserRoleUser),
		AutoGroups: []string{},
		Issued:     types.UserIssuedAPI,
	})
	require.NoError(t, err)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	_, _, _, _, err = manager.AddPeer(ctx, "", "", created.ID, &nbpeer.Peer{
		Key:  key.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "reset-user-peer"},
	}, false)
	require.NoError(t, err)

	require.NoError(t, manager.UpdateUserPassword(ctx, account.Id, ownerID, created.ID, "", "ResetPass1!"))
	user, err := manager.Store.GetUserByUserID(ctx, store.LockingStrengthNone, created.ID)
	require.NoError(t, err)
	require.True(t, user.ForcePasswordChange)
	peer, err := manager.Store.GetPeerByPeerPubKey(ctx, store.LockingStrengthNone, key.PublicKey().String())
	require.NoError(t, err)
	require.True(t, peer.Status.LoginExpired)
}
