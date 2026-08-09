package syncstore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestDiskStoreRedactsTunnelProfileKeys(t *testing.T) {
	topLevelKey := bytes.Repeat([]byte{0x4a}, 32)
	networkMapKey := bytes.Repeat([]byte{0x5b}, 32)
	response := &mgmProto.SyncResponse{
		PeerConfig: &mgmProto.PeerConfig{
			TunnelProfile: &mgmProto.TunnelProfile{
				ProtocolVersion:     "awg3",
				Revision:            7,
				HeaderProtectionKey: topLevelKey,
			},
		},
		NetworkMap: &mgmProto.NetworkMap{
			PeerConfig: &mgmProto.PeerConfig{
				TunnelProfile: &mgmProto.TunnelProfile{
					ProtocolVersion:     "awg3",
					Revision:            8,
					HeaderProtectionKey: networkMapKey,
				},
			},
		},
	}
	dir := t.TempDir()
	store := NewDiskStore(dir)

	require.NoError(t, store.Set(response))
	require.Equal(t, topLevelKey, response.PeerConfig.TunnelProfile.HeaderProtectionKey)
	require.Equal(
		t,
		networkMapKey,
		response.NetworkMap.PeerConfig.TunnelProfile.HeaderProtectionKey,
	)

	storedBytes, err := os.ReadFile(filepath.Join(dir, syncResponseFileName))
	require.NoError(t, err)
	require.NotContains(t, storedBytes, topLevelKey)
	require.NotContains(t, storedBytes, networkMapKey)

	stored, err := store.Get()
	require.NoError(t, err)
	require.Empty(t, stored.PeerConfig.TunnelProfile.HeaderProtectionKey)
	require.Empty(t, stored.NetworkMap.PeerConfig.TunnelProfile.HeaderProtectionKey)
	require.Equal(t, uint64(7), stored.PeerConfig.TunnelProfile.Revision)
	require.Equal(t, uint64(8), stored.NetworkMap.PeerConfig.TunnelProfile.Revision)
}
