//go:build linux && !android

package configurer

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	awgKernelDeviceFlags uint16 = 5

	awgKernelDeviceFlagReplacePeers uint32 = 1 << 0
	awgKernelPeerFlagRemove         uint32 = 1 << 0
	awgKernelPeerFlagReplaceIPs     uint32 = 1 << 1
	awgKernelPeerFlagUpdateOnly     uint32 = 1 << 2
)

var _ kernelControl = (*awgKernelCapabilityControl)(nil)

func (c *awgKernelCapabilityControl) ConfigureDevice(
	name string,
	config wgtypes.Config,
) error {
	attributes, err := encodeAWGKernelConfig(name, config, nil)
	if err != nil {
		return err
	}
	return c.setDevice(attributes)
}

func (c *awgKernelCapabilityControl) ConfigurePeer(
	name string,
	peer wgtypes.PeerConfig,
	persistentKeepaliveRange *uint32,
) error {
	var ranges map[wgtypes.Key]uint32
	if persistentKeepaliveRange != nil {
		ranges = map[wgtypes.Key]uint32{
			peer.PublicKey: *persistentKeepaliveRange,
		}
	}
	attributes, err := encodeAWGKernelConfig(
		name,
		wgtypes.Config{Peers: []wgtypes.PeerConfig{peer}},
		ranges,
	)
	if err != nil {
		return err
	}
	return c.setDevice(attributes)
}

func (c *awgKernelCapabilityControl) setDevice(attributes []byte) error {
	_, err := c.conn.Execute(genetlink.Message{
		Header: genetlink.Header{
			Command: awgKernelCommandSetDevice,
			Version: awgKernelFamilyVersion,
		},
		Data: attributes,
	}, c.family.ID, netlink.Request|netlink.Acknowledge)
	if err != nil {
		return normalizeAWGKernelNetlinkError(err)
	}
	return nil
}

func encodeAWGKernelConfig(
	name string,
	config wgtypes.Config,
	persistentKeepaliveRanges map[wgtypes.Key]uint32,
) ([]byte, error) {
	encoder := netlink.NewAttributeEncoder()
	encoder.String(awgKernelDeviceIfName, name)
	if config.PrivateKey != nil {
		encoder.Bytes(awgKernelDevicePrivateKey, config.PrivateKey[:])
	}
	if config.ListenPort != nil {
		encoder.Uint16(awgKernelDeviceListenPort, uint16(*config.ListenPort))
	}
	if config.FirewallMark != nil {
		encoder.Uint32(awgKernelDeviceFWMark, uint32(*config.FirewallMark))
	}
	if config.ReplacePeers {
		encoder.Uint32(awgKernelDeviceFlags, awgKernelDeviceFlagReplacePeers)
	}
	if len(config.Peers) > 0 {
		encoder.Nested(awgKernelDevicePeers, func(peers *netlink.AttributeEncoder) error {
			for i, peer := range config.Peers {
				rangeOverride, hasOverride := persistentKeepaliveRanges[peer.PublicKey]
				peers.Nested(
					uint16(i),
					encodeAWGKernelPeer(peer, rangeOverride, hasOverride),
				)
			}
			return nil
		})
	}
	return encoder.Encode()
}

func encodeAWGKernelPeer(
	peer wgtypes.PeerConfig,
	persistentKeepaliveRange uint32,
	hasKeepaliveOverride bool,
) func(*netlink.AttributeEncoder) error {
	return func(encoder *netlink.AttributeEncoder) error {
		encoder.Bytes(uint16(awgKernelPeerPublicKey), peer.PublicKey[:])
		var flags uint32
		if peer.Remove {
			flags |= awgKernelPeerFlagRemove
		}
		if peer.ReplaceAllowedIPs {
			flags |= awgKernelPeerFlagReplaceIPs
		}
		if peer.UpdateOnly {
			flags |= awgKernelPeerFlagUpdateOnly
		}
		if flags != 0 {
			encoder.Uint32(uint16(awgKernelPeerFlags), flags)
		}
		if peer.PresharedKey != nil {
			encoder.Bytes(uint16(awgKernelPeerPresharedKey), peer.PresharedKey[:])
		}
		if peer.Endpoint != nil {
			encoder.Do(uint16(awgKernelPeerEndpoint), encodeAWGKernelSockaddr(*peer.Endpoint))
		}
		if hasKeepaliveOverride {
			encoder.Uint32(
				uint16(awgKernelPeerPersistentKeepalive),
				persistentKeepaliveRange,
			)
		} else if peer.PersistentKeepaliveInterval != nil {
			seconds := uint64(peer.PersistentKeepaliveInterval.Seconds())
			if seconds > uint64(^uint16(0)) {
				return fmt.Errorf("persistent keepalive exceeds %d seconds", ^uint16(0))
			}
			value := uint16(seconds)
			encoder.Uint32(
				uint16(awgKernelPeerPersistentKeepalive),
				packAWGKernelRange16(value, value),
			)
		}
		if len(peer.AllowedIPs) > 0 {
			encoder.Nested(
				uint16(awgKernelPeerAllowedIPs),
				encodeAWGKernelAllowedIPs(peer.AllowedIPs),
			)
		}
		return nil
	}
}

func encodeAWGKernelAllowedIPs(
	allowedIPs []net.IPNet,
) func(*netlink.AttributeEncoder) error {
	return func(encoder *netlink.AttributeEncoder) error {
		for i, allowedIP := range allowedIPs {
			if allowedIP.IP.To16() == nil {
				return fmt.Errorf("invalid allowed IP %s", allowedIP.IP)
			}
			family := uint16(unix.AF_INET6)
			if allowedIP.IP.To4() != nil {
				family = unix.AF_INET
				allowedIP.IP = allowedIP.IP.To4()
			}
			encoder.Nested(uint16(i), func(ip *netlink.AttributeEncoder) error {
				ip.Uint16(uint16(awgKernelAllowedIPFamily), family)
				ip.Bytes(uint16(awgKernelAllowedIPAddress), allowedIP.IP)
				ones, _ := allowedIP.Mask.Size()
				ip.Uint8(uint16(awgKernelAllowedIPCIDRMask), uint8(ones))
				return nil
			})
		}
		return nil
	}
}

func encodeAWGKernelSockaddr(endpoint net.UDPAddr) func() ([]byte, error) {
	return func() ([]byte, error) {
		if endpoint.IP.To16() == nil {
			return nil, fmt.Errorf("invalid endpoint IP %s", endpoint.IP)
		}
		if endpoint.IP.To4() == nil {
			var address [16]byte
			copy(address[:], endpoint.IP.To16())
			sockaddr := unix.RawSockaddrInet6{
				Family: unix.AF_INET6,
				Port:   awgKernelSockaddrPort(endpoint.Port),
				Addr:   address,
			}
			return (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&sockaddr)))[:], nil
		}
		var address [4]byte
		copy(address[:], endpoint.IP.To4())
		sockaddr := unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   awgKernelSockaddrPort(endpoint.Port),
			Addr:   address,
		}
		return (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&sockaddr)))[:], nil
	}
}

func packAWGKernelRange16(low, high uint16) uint32 {
	return uint32(high)<<16 | uint32(low)
}
