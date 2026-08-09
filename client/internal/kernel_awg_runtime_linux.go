//go:build linux && !android && hybrid_awg

package internal

import (
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/tunnel"
	"github.com/netbirdio/netbird/client/system"
)

func shouldUseKernelAWG(profile *tunnel.Profile) bool {
	return profile != nil && !netstack.IsEnabled()
}

func prepareKernelAWGRuntime(
	profile *tunnel.Profile,
	runtime *system.TunnelRuntimeInfo,
) {
	if !shouldUseKernelAWG(profile) || runtime == nil {
		return
	}
	runtime.AdapterRevision = tunnel.KernelAdapterRevision
	runtime.Ready = false
}

func markKernelAWGUnavailable() {
	system.MarkKernelAWGUnavailable()
}
