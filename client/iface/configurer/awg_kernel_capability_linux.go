//go:build linux && !android

package configurer

import (
	"errors"
	"fmt"
	"os"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
)

const (
	awgKernelFamilyName    = "amneziawg"
	awgKernelFamilyVersion = 3

	awgKernelCommandGetDevice uint8 = iota
	awgKernelCommandSetDevice

	awgKernelDeviceIfName       uint16 = 2
	awgKernelDeviceCapabilities uint16 = 35

	awgKernelCapabilityPerPeerTransportMode AWGKernelCapabilities = 1 << 0
)

var (
	// ErrAWGKernelUnavailable indicates that the AmneziaWG generic-netlink
	// family is unavailable or incompatible.
	ErrAWGKernelUnavailable = errors.New("amneziawg kernel control is unavailable")
)

// AWGKernelCapabilities contains the optional features advertised by an
// AmneziaWG kernel interface.
type AWGKernelCapabilities uint64

// SupportsPerPeerTransportMode reports whether peers on one interface can use
// Standard WireGuard and AmneziaWG wire formats independently.
func (c AWGKernelCapabilities) SupportsPerPeerTransportMode() bool {
	return c&awgKernelCapabilityPerPeerTransportMode != 0
}

// QueryAWGKernelCapabilities reads the capabilities advertised by an existing
// AmneziaWG kernel interface.
func QueryAWGKernelCapabilities(deviceName string) (AWGKernelCapabilities, error) {
	control, err := newAWGKernelCapabilityControl()
	if err != nil {
		return 0, fmt.Errorf("open AmneziaWG kernel control: %w", err)
	}

	capabilities, queryErr := control.capabilities(deviceName)
	closeErr := control.Close()
	if queryErr != nil {
		return 0, fmt.Errorf("query AmneziaWG kernel capabilities: %w", queryErr)
	}
	if closeErr != nil {
		return 0, fmt.Errorf("close AmneziaWG kernel control: %w", closeErr)
	}
	return capabilities, nil
}

type awgKernelCapabilityControl struct {
	conn   *genetlink.Conn
	family genetlink.Family
}

func newAWGKernelCapabilityControl() (*awgKernelCapabilityControl, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}

	family, err := conn.GetFamily(awgKernelFamilyName)
	if err != nil {
		_ = conn.Close()
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT) {
			return nil, ErrAWGKernelUnavailable
		}
		return nil, err
	}
	if family.Version != awgKernelFamilyVersion {
		_ = conn.Close()
		return nil, fmt.Errorf(
			"%w: generic-netlink family version %d, expected %d",
			ErrAWGKernelUnavailable,
			family.Version,
			awgKernelFamilyVersion,
		)
	}

	return &awgKernelCapabilityControl{conn: conn, family: family}, nil
}

func (c *awgKernelCapabilityControl) Close() error {
	return c.conn.Close()
}

func (c *awgKernelCapabilityControl) capabilities(
	deviceName string,
) (AWGKernelCapabilities, error) {
	messages, err := c.getDevice(deviceName)
	if err != nil {
		return 0, err
	}
	return parseAWGKernelCapabilities(messages)
}

func (c *awgKernelCapabilityControl) getDevice(
	deviceName string,
) ([]genetlink.Message, error) {
	if deviceName == "" {
		return nil, os.ErrNotExist
	}

	attributes, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: awgKernelDeviceIfName,
		Data: nlenc.Bytes(deviceName),
	}})
	if err != nil {
		return nil, err
	}

	messages, err := c.conn.Execute(genetlink.Message{
		Header: genetlink.Header{
			Command: awgKernelCommandGetDevice,
			Version: awgKernelFamilyVersion,
		},
		Data: attributes,
	}, c.family.ID, netlink.Request|netlink.Dump)
	if err != nil {
		return nil, normalizeAWGKernelNetlinkError(err)
	}
	return messages, nil
}

func parseAWGKernelCapabilities(
	messages []genetlink.Message,
) (AWGKernelCapabilities, error) {
	var capabilities AWGKernelCapabilities
	for _, message := range messages {
		decoder, err := netlink.NewAttributeDecoder(message.Data)
		if err != nil {
			return 0, err
		}
		for decoder.Next() {
			if decoder.Type() == awgKernelDeviceCapabilities {
				capabilities = AWGKernelCapabilities(decoder.Uint64())
			}
		}
		if err := decoder.Err(); err != nil {
			return 0, err
		}
	}
	return capabilities, nil
}

func normalizeAWGKernelNetlinkError(err error) error {
	var operationError *netlink.OpError
	if !errors.As(err, &operationError) {
		return fmt.Errorf("AmneziaWG netlink operation: %w", err)
	}
	if errors.Is(operationError.Err, unix.ENODEV) ||
		errors.Is(operationError.Err, unix.ENOTSUP) {
		return os.ErrNotExist
	}
	return operationError.Err
}
