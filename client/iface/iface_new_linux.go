//go:build linux && !android

package iface

import (
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(opts WGIFaceOpts) (*WGIface, error) {
	return newWGIFaceLinux(
		opts,
		netstack.IsEnabled(),
		device.ProbeAWGKernel,
		newAWGKernelDevice,
	)
}

type awgKernelDeviceFactory func(WGIFaceOpts) WGTunDevice

func newWGIFaceLinux(
	opts WGIFaceOpts,
	netstackEnabled bool,
	probeAWGKernel func() error,
	awgDeviceFactory awgKernelDeviceFactory,
) (*WGIface, error) {
	if netstackEnabled {
		iceBind := bind.NewICEBind(opts.TransportNet, opts.Address, opts.MTU)
		return &WGIface{
			tun:            device.NewNetstackDevice(opts.IFaceName, opts.Address, opts.WGPort, opts.WGPrivKey, opts.MTU, iceBind, netstack.ListenAddr()),
			userspaceBind:  true,
			wgProxyFactory: wgproxy.NewUSPFactory(iceBind, opts.MTU),
		}, nil
	}
	if opts.UseAWGKernel {
		if err := probeAWGKernel(); err != nil {
			return nil, fmt.Errorf("probe AmneziaWG kernel backend: %w", err)
		}
		return &WGIface{
			tun:            awgDeviceFactory(opts),
			wgProxyFactory: wgproxy.NewKernelFactory(opts.WGPort, opts.MTU),
		}, nil
	}

	if device.WireGuardModuleIsLoaded() && !opts.ForceUserspace {
		return &WGIface{
			tun:            device.NewKernelDevice(opts.IFaceName, opts.Address, opts.WGPort, opts.WGPrivKey, opts.MTU, opts.TransportNet),
			wgProxyFactory: wgproxy.NewKernelFactory(opts.WGPort, opts.MTU),
		}, nil
	}

	if device.ModuleTunIsLoaded() {
		iceBind := bind.NewICEBind(opts.TransportNet, opts.Address, opts.MTU)
		return &WGIface{
			tun:            device.NewTunDevice(opts.IFaceName, opts.Address, opts.WGPort, opts.WGPrivKey, opts.MTU, iceBind),
			userspaceBind:  true,
			wgProxyFactory: wgproxy.NewUSPFactory(iceBind, opts.MTU),
		}, nil
	}

	return nil, errors.New("tun module not available")
}

func newAWGKernelDevice(opts WGIFaceOpts) WGTunDevice {
	return device.NewAWGKernelDevice(
		opts.IFaceName,
		opts.Address,
		opts.WGPort,
		opts.WGPrivKey,
		opts.MTU,
		opts.TransportNet,
	)
}
