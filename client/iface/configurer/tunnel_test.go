package configurer

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/netbirdio/netbird/client/iface/tunnel"
)

func TestTunnelProfileUAPIIncludesEmptyIPackets(t *testing.T) {
	profile := &tunnel.Profile{
		ProtocolVersion: tunnel.ProtocolAmneziaWG2,
		Revision:        9,
		AWG2: tunnel.AWG2Parameters{
			InitiationHeader: "101",
			ResponseHeader:   "102",
			CookieHeader:     "103",
			TransportHeader:  "104",
		},
	}

	config, err := tunnelProfileUAPI(profile)
	if err != nil {
		t.Fatalf("build profile UAPI: %v", err)
	}
	for _, key := range []string{"i1=", "i2=", "i3=", "i4=", "i5="} {
		if !strings.Contains(config, key+"\n") {
			t.Errorf("profile UAPI is missing %q", key)
		}
	}
}

func TestPeerTunnelModeUAPIRejectsStandardRevision(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))

	if _, err := peerTunnelModeUAPI(key, tunnel.ModeStandard, 1); err == nil {
		t.Fatal("standard tunnel mode accepted a non-zero profile revision")
	}
}

func TestTunnelProfileUAPIIncludesAWG3Parameters(t *testing.T) {
	profile := &tunnel.Profile{
		ProtocolVersion: tunnel.ProtocolAmneziaWG3,
		Revision:        9,
		AWG2: tunnel.AWG2Parameters{
			InitiationPadding: 12,
			ResponsePadding:   12,
			CookiePadding:     12,
			TransportPadding:  12,
			InitiationHeader:  "101",
			ResponseHeader:    "102",
			CookieHeader:      "103",
			TransportHeader:   "104",
		},
		AWG3: tunnel.AWG3Parameters{
			ContentPaddingAddition:      "1-32",
			PersistentKeepaliveInterval: "20-30",
			RekeyAfterTime:              "120-180",
			MaxHandshakeAttempts:        "5-10",
		},
	}
	copy(
		profile.HeaderProtectionKey[:],
		bytes.Repeat([]byte{0x37}, len(profile.HeaderProtectionKey)),
	)

	config, err := tunnelProfileUAPI(profile)
	if err != nil {
		t.Fatalf("build AWG3 profile UAPI: %v", err)
	}
	for _, line := range []string{
		"header_protection_key=" + strings.Repeat("37", 32),
		"content_padding_addition=1-32",
		"awg_persistent_keepalive_interval=20-30",
		"rekey_after_time=120-180",
		"max_handshake_attempts=5-10",
	} {
		if !strings.Contains(config, line+"\n") {
			t.Fatalf("AWG3 profile UAPI is missing a required field")
		}
	}
}
