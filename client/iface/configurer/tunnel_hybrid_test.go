//go:build hybrid_awg

package configurer

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/tunnel"
)

func TestHybridConfigurerPublishesProfileAndPeerMode(t *testing.T) {
	tunDevice := tuntest.NewChannelTUN()
	wgDevice := device.NewDevice(
		tunDevice.TUN(),
		conn.NewDefaultBind(),
		device.NewLogger(device.LogLevelError, "hybrid-test: "),
	)
	t.Cleanup(wgDevice.Close)

	configurer := NewUSPConfigurerNoUAPI(wgDevice, "hybrid-test", nil)
	profile := &tunnel.Profile{
		ProtocolVersion: tunnel.ProtocolAmneziaWG2,
		Revision:        5,
		AWG2: tunnel.AWG2Parameters{
			InitiationHeader: "1001",
			ResponseHeader:   "1002",
			CookieHeader:     "1003",
			TransportHeader:  "1004",
		},
	}
	if err := configurer.ConfigureTunnelProfile(profile); err != nil {
		t.Fatalf("configure tunnel profile: %v", err)
	}

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate peer key: %v", err)
	}
	peerKey := privateKey.PublicKey().String()
	if err := configurer.SetPeerTunnelMode(
		peerKey,
		tunnel.ModeAmneziaWG,
		profile.Revision,
	); err != nil {
		t.Fatalf("configure peer tunnel mode: %v", err)
	}

	config, err := wgDevice.IpcGet()
	if err != nil {
		t.Fatalf("read WireGuard UAPI: %v", err)
	}
	for _, expected := range []string{
		"awg_profile_revision=5",
		"transport_mode=amneziawg",
	} {
		if !strings.Contains(config, expected) {
			t.Errorf("WireGuard UAPI does not contain %q", expected)
		}
	}
}
