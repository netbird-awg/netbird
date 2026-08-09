//go:build linux && !android

package device

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

func TestNewAWGKernelDeviceUsesAmneziaWGLink(t *testing.T) {
	device := NewAWGKernelDevice("wt0", wgaddr.Address{}, 0, "", 1280, nil)

	assert.Equal(t, "amneziawg", device.linkFactory("wt0").Type())
	assert.NotNil(t, device.configurerFactory)
}

func TestNewKernelDeviceUsesWireGuardLink(t *testing.T) {
	device := NewKernelDevice("wt0", wgaddr.Address{}, 0, "", 1280, nil)

	assert.Equal(t, "wireguard", device.linkFactory("wt0").Type())
	assert.NotNil(t, device.configurerFactory)
}
