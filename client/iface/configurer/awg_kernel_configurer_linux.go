//go:build linux && !android

package configurer

import (
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/tunnel"
)

var (
	// ErrAWGKernelPerPeerModeUnavailable indicates that the kernel module does
	// not implement NetBird's per-peer transport mode.
	ErrAWGKernelPerPeerModeUnavailable = errors.New(
		"amneziawg kernel per-peer transport mode is unavailable",
	)
)

type awgKernelControl interface {
	kernelControl
	capabilities(deviceName string) (AWGKernelCapabilities, error)
	ConfigurePeerTransport(
		deviceName string,
		peerKey wgtypes.Key,
		mode awgKernelTransportMode,
		profileRevision uint64,
		persistentKeepaliveRange uint32,
	) error
	ConfigureTunnelProfile(deviceName string, profile *tunnel.Profile) error
}

type awgKernelControlFactory func() (awgKernelControl, error)

type awgKernelPeerState struct {
	mode            tunnel.Mode
	profileRevision uint64
	keepAlive       time.Duration
}

// AWGKernelConfigurer configures an amneziawg Linux kernel interface.
type AWGKernelConfigurer struct {
	*KernelConfigurer

	awgControlFactory awgKernelControlFactory
	stateMu           sync.RWMutex
	profileKeepalive  uint32
	peerStates        map[wgtypes.Key]awgKernelPeerState
}

// NewAWGKernelConfigurer verifies per-peer transport support and creates a
// configurer for an existing amneziawg interface.
func NewAWGKernelConfigurer(deviceName string) (*AWGKernelConfigurer, error) {
	return newAWGKernelConfigurer(deviceName, newAWGKernelControl)
}

func newAWGKernelControl() (awgKernelControl, error) {
	return newAWGKernelCapabilityControl()
}

func newAWGKernelConfigurer(
	deviceName string,
	factory awgKernelControlFactory,
) (*AWGKernelConfigurer, error) {
	control, err := factory()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAWGKernelUnavailable, err)
	}
	capabilities, capabilityErr := control.capabilities(deviceName)
	closeErr := control.Close()
	if capabilityErr != nil {
		return nil, fmt.Errorf("query AmneziaWG kernel capabilities: %w", capabilityErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close AmneziaWG kernel control: %w", closeErr)
	}
	if !capabilities.SupportsPerPeerTransportMode() {
		return nil, ErrAWGKernelPerPeerModeUnavailable
	}

	baseFactory := func() (kernelControl, error) {
		return factory()
	}
	return &AWGKernelConfigurer{
		KernelConfigurer:  newKernelConfigurer(deviceName, baseFactory),
		awgControlFactory: factory,
		peerStates:        make(map[wgtypes.Key]awgKernelPeerState),
	}, nil
}

// ConfigureTunnelProfile publishes a validated profile to the kernel device.
func (c *AWGKernelConfigurer) ConfigureTunnelProfile(profile *tunnel.Profile) error {
	keepalive, err := awgKernelOptionalRange(profile)
	if err != nil {
		return err
	}
	control, err := c.awgControlFactory()
	if err != nil {
		return fmt.Errorf("open AmneziaWG kernel control: %w", err)
	}
	defer closeAWGKernelControl(control)

	if err := control.ConfigureTunnelProfile(c.deviceName, profile); err != nil {
		return fmt.Errorf("configure kernel tunnel profile: %w", err)
	}

	c.stateMu.Lock()
	c.profileKeepalive = keepalive
	c.stateMu.Unlock()
	return nil
}

// SetPeerTunnelMode selects the wire format for a kernel peer.
func (c *AWGKernelConfigurer) SetPeerTunnelMode(
	peerKey string,
	mode tunnel.Mode,
	profileRevision uint64,
) error {
	key, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return fmt.Errorf("parse peer key: %w", err)
	}
	kernelMode, err := awgKernelMode(mode, profileRevision)
	if err != nil {
		return err
	}

	c.stateMu.RLock()
	state := c.peerStates[key]
	keepalive, err := c.keepaliveRangeLocked(mode, state.keepAlive)
	c.stateMu.RUnlock()
	if err != nil {
		return err
	}

	control, err := c.awgControlFactory()
	if err != nil {
		return fmt.Errorf("open AmneziaWG kernel control: %w", err)
	}
	defer closeAWGKernelControl(control)

	if err := control.ConfigurePeerTransport(
		c.deviceName,
		key,
		kernelMode,
		profileRevision,
		keepalive,
	); err != nil {
		return fmt.Errorf("configure kernel peer tunnel mode: %w", err)
	}

	c.stateMu.Lock()
	state.mode = mode
	state.profileRevision = profileRevision
	c.peerStates[key] = state
	c.stateMu.Unlock()
	return nil
}

func (c *AWGKernelConfigurer) keepaliveRangeLocked(
	mode tunnel.Mode,
	keepAlive time.Duration,
) (uint32, error) {
	if mode == tunnel.ModeAmneziaWG3 && c.profileKeepalive != 0 {
		return c.profileKeepalive, nil
	}
	if keepAlive < 0 || keepAlive/time.Second > time.Duration(^uint16(0)) {
		return 0, fmt.Errorf(
			"persistent keepalive must be between 0 and %d seconds",
			^uint16(0),
		)
	}
	seconds := uint16(keepAlive / time.Second)
	return packAWGKernelRange16(seconds, seconds), nil
}

func closeAWGKernelControl(control awgKernelControl) {
	if err := control.Close(); err != nil {
		log.Debugf("failed to close AmneziaWG kernel control: %v", err)
	}
}

func awgKernelMode(
	mode tunnel.Mode,
	profileRevision uint64,
) (awgKernelTransportMode, error) {
	switch mode {
	case tunnel.ModeStandard:
		if profileRevision != 0 {
			return 0, errors.New("standard peer profile revision must be zero")
		}
		return awgKernelTransportStandard, nil
	case tunnel.ModeAmneziaWG2, tunnel.ModeAmneziaWG3:
		if profileRevision == 0 {
			return 0, errors.New("AmneziaWG peer profile revision must be positive")
		}
		return awgKernelTransportAmneziaWG, nil
	default:
		return 0, fmt.Errorf("unsupported tunnel mode %d", mode)
	}
}

func awgKernelOptionalRange(profile *tunnel.Profile) (uint32, error) {
	if err := profile.Validate(); err != nil {
		return 0, fmt.Errorf("validate tunnel profile: %w", err)
	}
	if profile.ProtocolVersion != tunnel.ProtocolAmneziaWG3 ||
		profile.AWG3.PersistentKeepaliveInterval == "" {
		return 0, nil
	}
	return parseAWGKernelRange16(profile.AWG3.PersistentKeepaliveInterval)
}
