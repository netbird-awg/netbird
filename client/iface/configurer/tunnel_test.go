package configurer

import (
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
