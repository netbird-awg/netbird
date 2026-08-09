//go:build linux && !android

package configurer

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestParseAWGKernelDevice(t *testing.T) {
	deviceKey := wgtypes.Key{1}
	peerKey := wgtypes.Key{2}
	encoder := netlink.NewAttributeEncoder()
	encoder.String(uint16(awgKernelDeviceIfName), "wt0")
	encoder.Bytes(uint16(awgKernelDevicePublicKey), deviceKey[:])
	encoder.Nested(uint16(awgKernelDevicePeers), func(peers *netlink.AttributeEncoder) error {
		peers.Nested(0, func(peer *netlink.AttributeEncoder) error {
			peer.Bytes(uint16(awgKernelPeerPublicKey), peerKey[:])
			peer.Uint64(uint16(awgKernelPeerRXBytes), 100)
			peer.Uint64(uint16(awgKernelPeerTXBytes), 200)
			peer.Uint32(uint16(awgKernelPeerPersistentKeepalive), 10)
			return nil
		})
		return nil
	})
	data, err := encoder.Encode()
	require.NoError(t, err)

	device, err := parseAWGKernelDevice([]genetlink.Message{{Data: data}})
	require.NoError(t, err)
	require.Equal(t, "wt0", device.Name)
	require.Equal(t, deviceKey, device.PublicKey)
	require.Len(t, device.Peers, 1)
	require.Equal(t, peerKey, device.Peers[0].PublicKey)
	require.Equal(t, int64(100), device.Peers[0].ReceiveBytes)
	require.Equal(t, int64(200), device.Peers[0].TransmitBytes)
	require.Equal(t, 10*time.Second, device.Peers[0].PersistentKeepaliveInterval)
}

func TestParseAWGKernelDeviceMergesDumpParts(t *testing.T) {
	peerKey := wgtypes.Key{3}
	first := encodeAWGKernelPeerPart(t, peerKey, "10.0.0.1", 32)
	second := encodeAWGKernelPeerPart(t, peerKey, "fd00::1", 128)

	device, err := parseAWGKernelDevice([]genetlink.Message{{Data: first}, {Data: second}})
	require.NoError(t, err)
	require.Len(t, device.Peers, 1)
	require.Len(t, device.Peers[0].AllowedIPs, 2)
}

func TestParseAWGKernelDeviceRequiresDumpMessage(t *testing.T) {
	_, err := parseAWGKernelDevice(nil)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func encodeAWGKernelPeerPart(
	t *testing.T,
	peerKey wgtypes.Key,
	address string,
	mask uint8,
) []byte {
	t.Helper()
	encoder := netlink.NewAttributeEncoder()
	encoder.Nested(uint16(awgKernelDevicePeers), func(peers *netlink.AttributeEncoder) error {
		peers.Nested(0, func(peer *netlink.AttributeEncoder) error {
			peer.Bytes(uint16(awgKernelPeerPublicKey), peerKey[:])
			peer.Nested(
				uint16(awgKernelPeerAllowedIPs),
				func(allowedIPs *netlink.AttributeEncoder) error {
					ip := net.ParseIP(address)
					family := uint16(10)
					value := ip.To16()
					if ip.To4() != nil {
						family = 2
						value = ip.To4()
					}
					allowedIPs.Nested(0, func(allowedIP *netlink.AttributeEncoder) error {
						allowedIP.Uint16(uint16(awgKernelAllowedIPFamily), family)
						allowedIP.Bytes(uint16(awgKernelAllowedIPAddress), value)
						allowedIP.Uint8(uint16(awgKernelAllowedIPCIDRMask), mask)
						return nil
					})
					return nil
				},
			)
			return nil
		})
		return nil
	})
	data, err := encoder.Encode()
	require.NoError(t, err)
	return data
}
