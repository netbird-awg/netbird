//go:build !linux || android || !hybrid_awg

package internal

import (
	"github.com/netbirdio/netbird/client/iface/tunnel"
	"github.com/netbirdio/netbird/client/system"
)

func shouldUseKernelAWG(*tunnel.Profile) bool {
	return false
}

func prepareKernelAWGRuntime(*tunnel.Profile, *system.TunnelRuntimeInfo) {}

func markKernelAWGUnavailable() {}
