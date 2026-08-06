//go:build hybrid_awg

package configurer

import (
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/bind"
)

func configureAuthenticatedActivity(
	wgDevice *device.Device,
	recorder *bind.ActivityRecorder,
) {
	if recorder == nil {
		return
	}
	recorder.UseAuthenticatedEvents()
	wgDevice.SetAuthenticatedPacketHandler(func(peerKey device.NoisePublicKey) {
		recorder.RecordPeer(wgtypes.Key(peerKey).String())
	})
}
