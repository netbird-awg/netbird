//go:build linux && !android

package configurer

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	awgKernelDevicePrivateKey uint16 = 3
	awgKernelDevicePublicKey  uint16 = 4
	awgKernelDeviceListenPort uint16 = 6
	awgKernelDeviceFWMark     uint16 = 7
	awgKernelDevicePeers      uint16 = 8
)

type awgKernelPeerAttribute uint16

const (
	awgKernelPeerUnspecified awgKernelPeerAttribute = iota
	awgKernelPeerPublicKey
	awgKernelPeerPresharedKey
	awgKernelPeerFlags
	awgKernelPeerEndpoint
	awgKernelPeerPersistentKeepalive
	awgKernelPeerLastHandshake
	awgKernelPeerRXBytes
	awgKernelPeerTXBytes
	awgKernelPeerAllowedIPs
	awgKernelPeerProtocolVersion
	awgKernelPeerAdvancedSecurity
	awgKernelPeerTransportMode
	awgKernelPeerProfileRevision
)

type awgKernelAllowedIPAttribute uint16

const (
	awgKernelAllowedIPUnspecified awgKernelAllowedIPAttribute = iota
	awgKernelAllowedIPFamily
	awgKernelAllowedIPAddress
	awgKernelAllowedIPCIDRMask
	awgKernelAllowedIPFlags
)

func (c *awgKernelCapabilityControl) Device(name string) (*wgtypes.Device, error) {
	messages, err := c.getDevice(name)
	if err != nil {
		return nil, err
	}
	return parseAWGKernelDevice(messages)
}

func parseAWGKernelDevice(messages []genetlink.Message) (*wgtypes.Device, error) {
	if len(messages) == 0 {
		return nil, os.ErrNotExist
	}

	var device wgtypes.Device
	knownPeers := make(map[wgtypes.Key]int)
	for i, message := range messages {
		part, err := parseAWGKernelDeviceMessage(message)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			device = *part
			for peerIndex := range device.Peers {
				knownPeers[device.Peers[peerIndex].PublicKey] = peerIndex
			}
			continue
		}
		for _, peer := range part.Peers {
			if peerIndex, ok := knownPeers[peer.PublicKey]; ok {
				device.Peers[peerIndex].AllowedIPs = append(
					device.Peers[peerIndex].AllowedIPs,
					peer.AllowedIPs...,
				)
				continue
			}
			device.Peers = append(device.Peers, peer)
			knownPeers[peer.PublicKey] = len(device.Peers) - 1
		}
	}
	return &device, nil
}

func parseAWGKernelDeviceMessage(message genetlink.Message) (*wgtypes.Device, error) {
	decoder, err := netlink.NewAttributeDecoder(message.Data)
	if err != nil {
		return nil, err
	}
	device := &wgtypes.Device{Type: wgtypes.LinuxKernel}
	for decoder.Next() {
		switch decoder.Type() {
		case awgKernelDeviceIfName:
			device.Name = decoder.String()
		case awgKernelDevicePrivateKey:
			decoder.Do(parseAWGKernelKey(&device.PrivateKey))
		case awgKernelDevicePublicKey:
			decoder.Do(parseAWGKernelKey(&device.PublicKey))
		case awgKernelDeviceListenPort:
			device.ListenPort = int(decoder.Uint16())
		case awgKernelDeviceFWMark:
			device.FirewallMark = int(decoder.Uint32())
		case awgKernelDevicePeers:
			decoder.Nested(func(peers *netlink.AttributeDecoder) error {
				for peers.Next() {
					peers.Nested(func(peer *netlink.AttributeDecoder) error {
						device.Peers = append(device.Peers, parseAWGKernelPeer(peer))
						return nil
					})
				}
				return peers.Err()
			})
		}
	}
	if err := decoder.Err(); err != nil {
		return nil, err
	}
	return device, nil
}

func parseAWGKernelPeer(decoder *netlink.AttributeDecoder) wgtypes.Peer {
	var peer wgtypes.Peer
	for decoder.Next() {
		switch awgKernelPeerAttribute(decoder.Type()) {
		case awgKernelPeerPublicKey:
			decoder.Do(parseAWGKernelKey(&peer.PublicKey))
		case awgKernelPeerPresharedKey:
			decoder.Do(parseAWGKernelKey(&peer.PresharedKey))
		case awgKernelPeerEndpoint:
			peer.Endpoint = &net.UDPAddr{}
			decoder.Do(parseAWGKernelSockaddr(peer.Endpoint))
		case awgKernelPeerPersistentKeepalive:
			value := decoder.Uint32()
			peer.PersistentKeepaliveInterval = time.Duration(uint16(value)) * time.Second
		case awgKernelPeerLastHandshake:
			decoder.Do(parseAWGKernelTimespec(&peer.LastHandshakeTime))
		case awgKernelPeerRXBytes:
			peer.ReceiveBytes = int64(decoder.Uint64())
		case awgKernelPeerTXBytes:
			peer.TransmitBytes = int64(decoder.Uint64())
		case awgKernelPeerAllowedIPs:
			decoder.Nested(parseAWGKernelAllowedIPs(&peer.AllowedIPs))
		case awgKernelPeerProtocolVersion:
			peer.ProtocolVersion = int(decoder.Uint32())
		}
	}
	return peer
}

func parseAWGKernelAllowedIPs(
	allowedIPs *[]net.IPNet,
) func(*netlink.AttributeDecoder) error {
	return func(decoder *netlink.AttributeDecoder) error {
		for decoder.Next() {
			decoder.Nested(func(ip *netlink.AttributeDecoder) error {
				var address net.IP
				var family, mask int
				for ip.Next() {
					switch awgKernelAllowedIPAttribute(ip.Type()) {
					case awgKernelAllowedIPFamily:
						family = int(ip.Uint16())
					case awgKernelAllowedIPAddress:
						ip.Do(parseAWGKernelAddress(&address))
					case awgKernelAllowedIPCIDRMask:
						mask = int(ip.Uint8())
					}
				}
				if err := ip.Err(); err != nil {
					return err
				}
				bits := 128
				if family == unix.AF_INET {
					bits = 32
				}
				*allowedIPs = append(*allowedIPs, net.IPNet{
					IP:   address,
					Mask: net.CIDRMask(mask, bits),
				})
				return nil
			})
		}
		return decoder.Err()
	}
}

func parseAWGKernelKey(key *wgtypes.Key) func([]byte) error {
	return func(value []byte) error {
		parsed, err := wgtypes.NewKey(value)
		if err != nil {
			return err
		}
		*key = parsed
		return nil
	}
}

func parseAWGKernelAddress(address *net.IP) func([]byte) error {
	return func(value []byte) error {
		if len(value) != net.IPv4len && len(value) != net.IPv6len {
			return fmt.Errorf("unexpected IP address size %d", len(value))
		}
		*address = append(net.IP(nil), value...)
		return nil
	}
}

func parseAWGKernelSockaddr(endpoint *net.UDPAddr) func([]byte) error {
	return func(value []byte) error {
		switch len(value) {
		case unix.SizeofSockaddrInet4:
			sockaddr := *(*unix.RawSockaddrInet4)(unsafe.Pointer(&value[0]))
			*endpoint = net.UDPAddr{
				IP:   net.IP(sockaddr.Addr[:]).To4(),
				Port: int(awgKernelSockaddrPort(int(sockaddr.Port))),
			}
		case unix.SizeofSockaddrInet6:
			sockaddr := *(*unix.RawSockaddrInet6)(unsafe.Pointer(&value[0]))
			*endpoint = net.UDPAddr{
				IP:   net.IP(sockaddr.Addr[:]),
				Port: int(awgKernelSockaddrPort(int(sockaddr.Port))),
			}
		default:
			return fmt.Errorf("unexpected sockaddr size %d", len(value))
		}
		return nil
	}
}

func awgKernelSockaddrPort(port int) uint16 {
	return binary.BigEndian.Uint16(nlenc.Uint16Bytes(uint16(port)))
}

type awgKernelTimespec32 struct {
	seconds     int32
	nanoseconds int32
}

type awgKernelTimespec64 struct {
	seconds     int64
	nanoseconds int64
}

func parseAWGKernelTimespec(target *time.Time) func([]byte) error {
	return func(value []byte) error {
		var seconds, nanoseconds int64
		switch len(value) {
		case int(unsafe.Sizeof(awgKernelTimespec32{})):
			timespec := *(*awgKernelTimespec32)(unsafe.Pointer(&value[0]))
			seconds = int64(timespec.seconds)
			nanoseconds = int64(timespec.nanoseconds)
		case int(unsafe.Sizeof(awgKernelTimespec64{})):
			timespec := *(*awgKernelTimespec64)(unsafe.Pointer(&value[0]))
			seconds = timespec.seconds
			nanoseconds = timespec.nanoseconds
		default:
			return fmt.Errorf("unexpected timespec size %d", len(value))
		}
		if seconds > 0 || nanoseconds > 0 {
			*target = time.Unix(seconds, nanoseconds)
		}
		return nil
	}
}
