//go:build linux && !android

package configurer

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mdlayher/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/tunnel"
)

const (
	awgKernelDeviceJunkPacketCount        uint16 = 9
	awgKernelDeviceJunkPacketMin          uint16 = 10
	awgKernelDeviceJunkPacketMax          uint16 = 11
	awgKernelDeviceInitiationPadding      uint16 = 12
	awgKernelDeviceResponsePadding        uint16 = 13
	awgKernelDeviceInitiationHeader       uint16 = 14
	awgKernelDeviceResponseHeader         uint16 = 15
	awgKernelDeviceCookieHeader           uint16 = 16
	awgKernelDeviceTransportHeader        uint16 = 17
	awgKernelDeviceCookiePadding          uint16 = 19
	awgKernelDeviceTransportPadding       uint16 = 20
	awgKernelDeviceIPacket1               uint16 = 21
	awgKernelDeviceIPacket2               uint16 = 22
	awgKernelDeviceIPacket3               uint16 = 23
	awgKernelDeviceIPacket4               uint16 = 24
	awgKernelDeviceIPacket5               uint16 = 25
	awgKernelDeviceHeaderProtectionKey    uint16 = 26
	awgKernelDeviceContentPaddingAddition uint16 = 27
	awgKernelDeviceRekeyAfterTime         uint16 = 28
	awgKernelDeviceRekeyTimeout           uint16 = 29
	awgKernelDeviceRejectAfterTime        uint16 = 30
	awgKernelDeviceKeepaliveTimeout       uint16 = 31
	awgKernelDeviceMaxHandshakeAttempts   uint16 = 32
	awgKernelDeviceProfileRevision        uint16 = 33
)

type awgKernelTransportMode uint8

const (
	awgKernelTransportStandard awgKernelTransportMode = iota
	awgKernelTransportAmneziaWG
)

func (c *awgKernelCapabilityControl) ConfigureTunnelProfile(
	name string,
	profile *tunnel.Profile,
) error {
	attributes, err := encodeAWGKernelProfile(name, profile)
	if err != nil {
		return err
	}
	return c.setDevice(attributes)
}

func (c *awgKernelCapabilityControl) ConfigurePeerTransport(
	name string,
	peerKey wgtypes.Key,
	mode awgKernelTransportMode,
	profileRevision uint64,
	persistentKeepaliveRange uint32,
) error {
	attributes, err := encodeAWGKernelPeerTransport(
		name,
		peerKey,
		mode,
		profileRevision,
		persistentKeepaliveRange,
	)
	if err != nil {
		return err
	}
	return c.setDevice(attributes)
}

func encodeAWGKernelPeerTransport(
	name string,
	peerKey wgtypes.Key,
	mode awgKernelTransportMode,
	profileRevision uint64,
	persistentKeepaliveRange uint32,
) ([]byte, error) {
	encoder := netlink.NewAttributeEncoder()
	encoder.String(awgKernelDeviceIfName, name)
	encoder.Nested(awgKernelDevicePeers, func(peers *netlink.AttributeEncoder) error {
		peers.Nested(0, func(peer *netlink.AttributeEncoder) error {
			peer.Bytes(uint16(awgKernelPeerPublicKey), peerKey[:])
			peer.Uint8(uint16(awgKernelPeerTransportMode), uint8(mode))
			peer.Uint64(uint16(awgKernelPeerProfileRevision), profileRevision)
			peer.Uint32(
				uint16(awgKernelPeerPersistentKeepalive),
				persistentKeepaliveRange,
			)
			return nil
		})
		return nil
	})
	return encoder.Encode()
}

func encodeAWGKernelProfile(name string, profile *tunnel.Profile) ([]byte, error) {
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("validate tunnel profile: %w", err)
	}
	parameters := profile.AWG2
	headers := []string{
		parameters.InitiationHeader,
		parameters.ResponseHeader,
		parameters.CookieHeader,
		parameters.TransportHeader,
	}
	encodedHeaders := make([]uint64, len(headers))
	for i, header := range headers {
		encoded, err := parseAWGKernelRange32(header)
		if err != nil {
			return nil, fmt.Errorf("parse H%d: %w", i+1, err)
		}
		encodedHeaders[i] = encoded
	}

	encoder := netlink.NewAttributeEncoder()
	encoder.String(awgKernelDeviceIfName, name)
	encoder.Uint16(awgKernelDeviceJunkPacketCount, uint16(parameters.JunkPacketCount))
	encoder.Uint16(awgKernelDeviceJunkPacketMin, uint16(parameters.JunkPacketMin))
	encoder.Uint16(awgKernelDeviceJunkPacketMax, uint16(parameters.JunkPacketMax))
	encoder.Uint16(awgKernelDeviceInitiationPadding, uint16(parameters.InitiationPadding))
	encoder.Uint16(awgKernelDeviceResponsePadding, uint16(parameters.ResponsePadding))
	encoder.Uint16(awgKernelDeviceCookiePadding, uint16(parameters.CookiePadding))
	encoder.Uint16(awgKernelDeviceTransportPadding, uint16(parameters.TransportPadding))
	encoder.Uint64(awgKernelDeviceInitiationHeader, encodedHeaders[0])
	encoder.Uint64(awgKernelDeviceResponseHeader, encodedHeaders[1])
	encoder.Uint64(awgKernelDeviceCookieHeader, encodedHeaders[2])
	encoder.Uint64(awgKernelDeviceTransportHeader, encodedHeaders[3])
	encoder.String(awgKernelDeviceIPacket1, parameters.IPacket1)
	encoder.String(awgKernelDeviceIPacket2, parameters.IPacket2)
	encoder.String(awgKernelDeviceIPacket3, parameters.IPacket3)
	encoder.String(awgKernelDeviceIPacket4, parameters.IPacket4)
	encoder.String(awgKernelDeviceIPacket5, parameters.IPacket5)
	encoder.Uint64(awgKernelDeviceProfileRevision, profile.Revision)

	if profile.ProtocolVersion == tunnel.ProtocolAmneziaWG3 {
		encoder.Bytes(
			awgKernelDeviceHeaderProtectionKey,
			profile.HeaderProtectionKey[:],
		)
	}
	if err := encodeAWGKernelTimingProfile(encoder, profile); err != nil {
		return nil, err
	}
	return encoder.Encode()
}

func encodeAWGKernelTimingProfile(
	encoder *netlink.AttributeEncoder,
	profile *tunnel.Profile,
) error {
	values := []struct {
		attribute uint16
		name      string
		value     string
	}{
		{
			awgKernelDeviceContentPaddingAddition,
			"content_padding_addition",
			profile.AWG3.ContentPaddingAddition,
		},
		{awgKernelDeviceRekeyAfterTime, "rekey_after_time", profile.AWG3.RekeyAfterTime},
		{awgKernelDeviceRekeyTimeout, "rekey_timeout", profile.AWG3.RekeyTimeout},
		{awgKernelDeviceRejectAfterTime, "reject_after_time", profile.AWG3.RejectAfterTime},
		{awgKernelDeviceKeepaliveTimeout, "keepalive_timeout", profile.AWG3.KeepaliveTimeout},
		{
			awgKernelDeviceMaxHandshakeAttempts,
			"max_handshake_attempts",
			profile.AWG3.MaxHandshakeAttempts,
		},
	}
	for _, value := range values {
		encoded, err := parseAWGKernelRange16(value.value)
		if err != nil {
			return fmt.Errorf("parse %s for kernel: %w", value.name, err)
		}
		encoder.Uint32(value.attribute, encoded)
	}
	return nil
}

func parseAWGKernelRange16(value string) (uint32, error) {
	low, high, err := parseAWGKernelRange(value, 16)
	if err != nil {
		return 0, err
	}
	return packAWGKernelRange16(uint16(low), uint16(high)), nil
}

func parseAWGKernelRange32(value string) (uint64, error) {
	low, high, err := parseAWGKernelRange(value, 32)
	if err != nil {
		return 0, err
	}
	return uint64(high)<<32 | low, nil
}

func parseAWGKernelRange(value string, bits int) (uint64, uint64, error) {
	if value == "" {
		return 0, 0, nil
	}
	parts := strings.Split(value, "-")
	if len(parts) == 0 || len(parts) > 2 {
		return 0, 0, errors.New("range must contain one value or two endpoints")
	}
	low, err := strconv.ParseUint(parts[0], 10, bits)
	if err != nil {
		return 0, 0, fmt.Errorf("parse lower endpoint: %w", err)
	}
	high := low
	if len(parts) == 2 {
		high, err = strconv.ParseUint(parts[1], 10, bits)
		if err != nil {
			return 0, 0, fmt.Errorf("parse upper endpoint: %w", err)
		}
	}
	if high < low {
		return 0, 0, errors.New("upper endpoint must not be smaller than lower endpoint")
	}
	return low, high, nil
}
