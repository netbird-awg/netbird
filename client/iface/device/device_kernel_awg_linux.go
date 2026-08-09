//go:build linux && !android

package device

import (
	"github.com/pion/transport/v3"

	"github.com/netbirdio/netbird/client/iface/configurer"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// NewAWGKernelDevice creates a Linux AmneziaWG kernel device.
func NewAWGKernelDevice(
	name string,
	address wgaddr.Address,
	wgPort int,
	key string,
	mtu uint16,
	transportNet transport.Net,
) *TunKernelDevice {
	return newKernelDevice(
		name,
		address,
		wgPort,
		key,
		mtu,
		transportNet,
		newAWGLink,
		func(deviceName string) (WGConfigurer, error) {
			return configurer.NewAWGKernelConfigurer(deviceName)
		},
	)
}
