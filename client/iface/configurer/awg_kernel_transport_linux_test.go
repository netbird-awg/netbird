//go:build linux && !android

package configurer

import (
	"bytes"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/tunnel"
)

func TestEncodeAWGKernelProfile(t *testing.T) {
	profile := testAWGKernelProfile()
	data, err := encodeAWGKernelProfile("wt0", profile)
	require.NoError(t, err)

	decoder, err := netlink.NewAttributeDecoder(data)
	require.NoError(t, err)
	var revision, initiationHeader uint64
	var rekeyAfterTime uint32
	var headerKey []byte
	for decoder.Next() {
		switch decoder.Type() {
		case awgKernelDeviceProfileRevision:
			revision = decoder.Uint64()
		case awgKernelDeviceInitiationHeader:
			initiationHeader = decoder.Uint64()
		case awgKernelDeviceRekeyAfterTime:
			rekeyAfterTime = decoder.Uint32()
		case awgKernelDeviceHeaderProtectionKey:
			headerKey = bytes.Clone(decoder.Bytes())
		}
	}
	require.NoError(t, decoder.Err())
	require.Equal(t, profile.Revision, revision)
	require.Equal(t, uint64(110)<<32|100, initiationHeader)
	require.Equal(t, packAWGKernelRange16(120, 180), rekeyAfterTime)
	require.Equal(t, profile.HeaderProtectionKey[:], headerKey)
}

func TestEncodeAWGKernelProfileRejectsWideTimingRange(t *testing.T) {
	profile := testAWGKernelProfile()
	profile.AWG3.RekeyAfterTime = "70000"
	require.NoError(t, profile.Validate())

	_, err := encodeAWGKernelProfile("wt0", profile)
	require.ErrorContains(t, err, "value out of range")
}

func TestEncodeAWGKernelPeerTransport(t *testing.T) {
	data, err := encodeAWGKernelPeerTransport(
		"wt0",
		wgtypes.Key{4, 5, 6},
		awgKernelTransportAmneziaWG,
		9,
		packAWGKernelRange16(10, 20),
	)
	require.NoError(t, err)

	decoder, err := netlink.NewAttributeDecoder(data)
	require.NoError(t, err)
	var mode uint8
	var revision uint64
	var keepalive uint32
	for decoder.Next() {
		if decoder.Type() != awgKernelDevicePeers {
			continue
		}
		decoder.Nested(func(peers *netlink.AttributeDecoder) error {
			for peers.Next() {
				peers.Nested(func(peer *netlink.AttributeDecoder) error {
					for peer.Next() {
						switch awgKernelPeerAttribute(peer.Type()) {
						case awgKernelPeerTransportMode:
							mode = peer.Uint8()
						case awgKernelPeerProfileRevision:
							revision = peer.Uint64()
						case awgKernelPeerPersistentKeepalive:
							keepalive = peer.Uint32()
						}
					}
					return peer.Err()
				})
			}
			return peers.Err()
		})
	}
	require.NoError(t, decoder.Err())
	require.Equal(t, uint8(awgKernelTransportAmneziaWG), mode)
	require.Equal(t, uint64(9), revision)
	require.Equal(t, packAWGKernelRange16(10, 20), keepalive)
}

func testAWGKernelProfile() *tunnel.Profile {
	profile := &tunnel.Profile{
		ProtocolVersion: tunnel.ProtocolAmneziaWG3,
		Revision:        9,
		AWG2: tunnel.AWG2Parameters{
			JunkPacketCount:   4,
			JunkPacketMin:     8,
			JunkPacketMax:     80,
			InitiationPadding: 16,
			ResponsePadding:   17,
			CookiePadding:     18,
			TransportPadding:  19,
			InitiationHeader:  "100-110",
			ResponseHeader:    "200-210",
			CookieHeader:      "300-310",
			TransportHeader:   "400-410",
		},
		AWG3: tunnel.AWG3Parameters{
			ContentPaddingAddition: "1-32",
			RekeyAfterTime:         "120-180",
			RekeyTimeout:           "5-10",
			RejectAfterTime:        "180-240",
			KeepaliveTimeout:       "10-20",
			MaxHandshakeAttempts:   "5-10",
		},
	}
	for i := range profile.HeaderProtectionKey {
		profile.HeaderProtectionKey[i] = 0x5a
	}
	return profile
}
