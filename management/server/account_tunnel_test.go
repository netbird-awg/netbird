package server

import (
	"bytes"
	"context"
	"encoding/json"
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
