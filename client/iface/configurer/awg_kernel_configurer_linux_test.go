//go:build linux && !android

package configurer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/tunnel"
)

func TestNewAWGKernelConfigurerRequiresPerPeerCapability(t *testing.T) {
	control := &fakeAWGKernelControl{}
	_, err := newAWGKernelConfigurer("wt0", fakeAWGKernelFactory(control))
	require.ErrorIs(t, err, ErrAWGKernelPerPeerModeUnavailable)

	control.capabilityBits = awgKernelCapabilityPerPeerTransportMode
	configurer, err := newAWGKernelConfigurer("wt0", fakeAWGKernelFactory(control))
	require.NoError(t, err)
	require.NotNil(t, configurer)
}

func TestAWGKernelConfigurerSelectsPeerKeepaliveRange(t *testing.T) {
	control := &fakeAWGKernelControl{
		capabilityBits: awgKernelCapabilityPerPeerTransportMode,
	}
	configurer, err := newAWGKernelConfigurer("wt0", fakeAWGKernelFactory(control))
	require.NoError(t, err)

	profile := testAWGKernelProfile()
	profile.AWG3.PersistentKeepaliveInterval = "10-20"
	require.NoError(t, configurer.ConfigureTunnelProfile(profile))

	key := wgtypes.Key{1, 2, 3}
	configurer.peerStates[key] = awgKernelPeerState{keepAlive: 25 * time.Second}
	require.NoError(t, configurer.SetPeerTunnelMode(
		key.String(),
		tunnel.ModeAmneziaWG3,
		profile.Revision,
	))
	require.Equal(
		t,
		packAWGKernelRange16(10, 20),
		control.transportCalls[0].persistentKeepalive,
	)

	require.NoError(t, configurer.SetPeerTunnelMode(
		key.String(),
		tunnel.ModeStandard,
		0,
	))
	require.Equal(
		t,
		packAWGKernelRange16(25, 25),
		control.transportCalls[1].persistentKeepalive,
	)
}

type fakeAWGKernelControl struct {
	capabilityBits AWGKernelCapabilities
	transportCalls []fakeAWGTransportCall
}

type fakeAWGTransportCall struct {
	mode                awgKernelTransportMode
	profileRevision     uint64
	persistentKeepalive uint32
}

func fakeAWGKernelFactory(control *fakeAWGKernelControl) awgKernelControlFactory {
	return func() (awgKernelControl, error) {
		return control, nil
	}
}

func (c *fakeAWGKernelControl) Close() error { return nil }

func (c *fakeAWGKernelControl) capabilities(
	string,
) (AWGKernelCapabilities, error) {
	return c.capabilityBits, nil
}

func (c *fakeAWGKernelControl) Device(string) (*wgtypes.Device, error) {
	return &wgtypes.Device{Name: "wt0"}, nil
}

func (c *fakeAWGKernelControl) ConfigureDevice(string, wgtypes.Config) error {
	return nil
}

func (c *fakeAWGKernelControl) ConfigureTunnelProfile(
	string,
	*tunnel.Profile,
) error {
	return nil
}

func (c *fakeAWGKernelControl) ConfigurePeerTransport(
	_ string,
	_ wgtypes.Key,
	mode awgKernelTransportMode,
	profileRevision uint64,
	persistentKeepalive uint32,
) error {
	c.transportCalls = append(c.transportCalls, fakeAWGTransportCall{
		mode:                mode,
		profileRevision:     profileRevision,
		persistentKeepalive: persistentKeepalive,
	})
	return nil
}
