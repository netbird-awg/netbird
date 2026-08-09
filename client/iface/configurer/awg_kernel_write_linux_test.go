//go:build linux && !android

package configurer

import (
	"net"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestEncodeAWGKernelConfig(t *testing.T) {
	privateKey := wgtypes.Key{1}
	peerKey := wgtypes.Key{2}
	port := 51820
	fwmark := 42
	keepalive := 15 * time.Second
	config := wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &port,
		FirewallMark: &fwmark,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   peerKey,
			ReplaceAllowedIPs:           true,
			PersistentKeepaliveInterval: &keepalive,
			Endpoint: &net.UDPAddr{
				IP:   net.ParseIP("192.0.2.1"),
				Port: 51820,
			},
			AllowedIPs: []net.IPNet{{
				IP:   net.ParseIP("10.0.0.0"),
				Mask: net.CIDRMask(24, 32),
			}},
		}},
	}

	data, err := encodeAWGKernelConfig("wt0", config, nil)
	require.NoError(t, err)

	decoder, err := netlink.NewAttributeDecoder(data)
	require.NoError(t, err)
	var name string
	var flags uint32
	var peers int
	var peerFlags uint32
	var peerKeepalive uint32
	var allowedIPs int
	for decoder.Next() {
		switch decoder.Type() {
		case awgKernelDeviceIfName:
			name = decoder.String()
		case awgKernelDeviceFlags:
			flags = decoder.Uint32()
		case awgKernelDevicePeers:
			decoder.Nested(func(nested *netlink.AttributeDecoder) error {
				for nested.Next() {
					peers++
					nested.Nested(func(peer *netlink.AttributeDecoder) error {
						for peer.Next() {
							switch awgKernelPeerAttribute(peer.Type()) {
							case awgKernelPeerFlags:
								peerFlags = peer.Uint32()
							case awgKernelPeerPersistentKeepalive:
								peerKeepalive = peer.Uint32()
							case awgKernelPeerAllowedIPs:
								peer.Nested(func(ips *netlink.AttributeDecoder) error {
									for ips.Next() {
										allowedIPs++
									}
									return ips.Err()
								})
							}
						}
						return peer.Err()
					})
				}
				return nested.Err()
			})
		}
	}
	require.NoError(t, decoder.Err())
	require.Equal(t, "wt0", name)
	require.Equal(t, awgKernelDeviceFlagReplacePeers, flags)
	require.Equal(t, 1, peers)
	require.Equal(t, awgKernelPeerFlagReplaceIPs, peerFlags)
	require.Equal(t, packAWGKernelRange16(15, 15), peerKeepalive)
	require.Equal(t, 1, allowedIPs)
}

func TestEncodeAWGKernelPeerRejectsLongKeepalive(t *testing.T) {
	keepalive := (time.Duration(^uint16(0)) + 1) * time.Second
	encoder := netlink.NewAttributeEncoder()
	err := encodeAWGKernelPeer(
		wgtypes.PeerConfig{PersistentKeepaliveInterval: &keepalive},
		0,
		false,
	)(encoder)
	require.Error(t, err)
}
