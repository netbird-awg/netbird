package configurer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/tunnel"
)

// ConfigureTunnelProfile publishes a validated AWG profile to the userspace
// WireGuard device.
func (c *WGUSPConfigurer) ConfigureTunnelProfile(profile *tunnel.Profile) error {
	config, err := tunnelProfileUAPI(profile)
	if err != nil {
		return err
	}
	if err := c.device.IpcSet(config); err != nil {
		return fmt.Errorf("configure tunnel profile: %w", err)
	}
	return nil
}

// SetPeerTunnelMode selects the wire format for a userspace WireGuard peer.
func (c *WGUSPConfigurer) SetPeerTunnelMode(
	peerKey string,
	mode tunnel.Mode,
	profileRevision uint64,
) error {
	config, err := peerTunnelModeUAPI(peerKey, mode, profileRevision)
	if err != nil {
		return err
	}
	if err := c.device.IpcSet(config); err != nil {
		return fmt.Errorf("configure peer tunnel mode: %w", err)
	}
	return nil
}

func tunnelProfileUAPI(profile *tunnel.Profile) (string, error) {
	if err := profile.Validate(); err != nil {
		return "", fmt.Errorf("validate tunnel profile: %w", err)
	}

	parameters := profile.AWG2
	var builder strings.Builder
	fmt.Fprintf(&builder, "awg_profile_revision=%d\n", profile.Revision)
	fmt.Fprintf(&builder, "jc=%d\n", parameters.JunkPacketCount)
	fmt.Fprintf(&builder, "jmin=%d\n", parameters.JunkPacketMin)
	fmt.Fprintf(&builder, "jmax=%d\n", parameters.JunkPacketMax)
	fmt.Fprintf(&builder, "s1=%d\n", parameters.InitiationPadding)
	fmt.Fprintf(&builder, "s2=%d\n", parameters.ResponsePadding)
	fmt.Fprintf(&builder, "s3=%d\n", parameters.CookiePadding)
	fmt.Fprintf(&builder, "s4=%d\n", parameters.TransportPadding)
	fmt.Fprintf(&builder, "h1=%s\n", parameters.InitiationHeader)
	fmt.Fprintf(&builder, "h2=%s\n", parameters.ResponseHeader)
	fmt.Fprintf(&builder, "h3=%s\n", parameters.CookieHeader)
	fmt.Fprintf(&builder, "h4=%s\n", parameters.TransportHeader)
	fmt.Fprintf(&builder, "i1=%s\n", parameters.IPacket1)
	fmt.Fprintf(&builder, "i2=%s\n", parameters.IPacket2)
	fmt.Fprintf(&builder, "i3=%s\n", parameters.IPacket3)
	fmt.Fprintf(&builder, "i4=%s\n", parameters.IPacket4)
	fmt.Fprintf(&builder, "i5=%s\n\n", parameters.IPacket5)
	return builder.String(), nil
}

func peerTunnelModeUAPI(
	peerKey string,
	mode tunnel.Mode,
	profileRevision uint64,
) (string, error) {
	key, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return "", fmt.Errorf("parse peer key: %w", err)
	}
	switch mode {
	case tunnel.ModeStandard:
		if profileRevision != 0 {
			return "", errors.New("standard peer profile revision must be zero")
		}
	case tunnel.ModeAmneziaWG:
		if profileRevision == 0 {
			return "", errors.New("AmneziaWG peer profile revision must be positive")
		}
	default:
		return "", fmt.Errorf("unsupported tunnel mode %d", mode)
	}

	return fmt.Sprintf(
		"public_key=%s\ntransport_mode=%s\nawg_profile_revision=%d\n\n",
		hex.EncodeToString(key[:]),
		mode,
		profileRevision,
	), nil
}
