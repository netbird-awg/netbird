//go:build (linux && !android) || freebsd

package configurer

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestKernelConfigurerUsesControlFactory(t *testing.T) {
	control := &fakeKernelControl{
		device: &wgtypes.Device{Name: "wt0"},
	}
	configurer := newKernelConfigurer("wt0", func() (kernelControl, error) {
		return control, nil
	})

	config := wgtypes.Config{ReplacePeers: true}
	require.NoError(t, configurer.configure(config))
	require.Equal(t, config, control.config)

	stats, err := configurer.FullStats()
	require.NoError(t, err)
	require.Equal(t, "wt0", stats.DeviceName)
	require.Equal(t, 2, control.closeCalls)
}

type fakeKernelControl struct {
	device     *wgtypes.Device
	config     wgtypes.Config
	closeCalls int
}

func (c *fakeKernelControl) Close() error {
	c.closeCalls++
	return nil
}

func (c *fakeKernelControl) ConfigureDevice(_ string, config wgtypes.Config) error {
	c.config = config
	return nil
}

func (c *fakeKernelControl) Device(_ string) (*wgtypes.Device, error) {
	return c.device, nil
}
