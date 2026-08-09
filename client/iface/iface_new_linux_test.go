//go:build linux && !android

package iface

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/device"
)

func TestNewWGIFaceLinuxRejectsUnavailableAWGKernel(t *testing.T) {
	probeErr := errors.New("probe failed")
	_, err := newWGIFaceLinux(
		WGIFaceOpts{UseAWGKernel: true},
		false,
		func() error { return probeErr },
		newAWGKernelDevice,
	)

	require.ErrorIs(t, err, probeErr)
}

func TestNewWGIFaceLinuxSelectsAWGKernel(t *testing.T) {
	probed := false
	created := false
	wgIface, err := newWGIFaceLinux(
		WGIFaceOpts{
			IFaceName:      "wt0",
			MTU:            DefaultMTU,
			ForceUserspace: true,
			UseAWGKernel:   true,
		},
		false,
		func() error {
			probed = true
			return nil
		},
		func(opts WGIFaceOpts) WGTunDevice {
			created = true
			return newAWGKernelDevice(opts)
		},
	)

	require.NoError(t, err)
	assert.True(t, probed, "AWG kernel backend should be probed")
	assert.True(t, created, "AWG kernel device should be created")
	assert.IsType(t, &device.TunKernelDevice{}, wgIface.tun)
	assert.False(t, wgIface.userspaceBind, "kernel backend should not use userspace bind")
}
