//go:build !hybrid_awg

package configurer

import (
	"golang.zx2c4.com/wireguard/device"

	"github.com/netbirdio/netbird/client/iface/bind"
)

func configureAuthenticatedActivity(
	_ *device.Device,
	_ *bind.ActivityRecorder,
) {
}
