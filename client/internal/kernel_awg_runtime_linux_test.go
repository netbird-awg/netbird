//go:build linux && !android && hybrid_awg

package internal

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/iface/tunnel"
	"github.com/netbirdio/netbird/client/system"
)

func TestPrepareKernelAWGRuntimeWaitsForKernelConfiguration(t *testing.T) {
	t.Setenv("NB_USE_NETSTACK_MODE", "false")
	profile := &tunnel.Profile{}
	runtime := &system.TunnelRuntimeInfo{
		AdapterRevision: tunnel.AdapterRevision,
		Ready:           true,
	}

	prepareKernelAWGRuntime(profile, runtime)

	assert.True(t, shouldUseKernelAWG(profile))
	assert.Equal(t, tunnel.KernelAdapterRevision, runtime.AdapterRevision)
	assert.False(t, runtime.Ready, "kernel runtime must wait for profile acceptance")
}

func TestPrepareKernelAWGRuntimePreservesNetstack(t *testing.T) {
	t.Setenv("NB_USE_NETSTACK_MODE", "true")
	profile := &tunnel.Profile{}
	runtime := &system.TunnelRuntimeInfo{
		AdapterRevision: tunnel.AdapterRevision,
		Ready:           true,
	}

	prepareKernelAWGRuntime(profile, runtime)

	assert.False(t, shouldUseKernelAWG(profile))
	assert.Equal(t, tunnel.AdapterRevision, runtime.AdapterRevision)
	assert.True(t, runtime.Ready, "netstack runtime should remain userspace-ready")
}

func TestMarkKernelAWGRuntimeReadyAfterProfileAcceptance(t *testing.T) {
	t.Setenv("NB_USE_NETSTACK_MODE", "false")
	profile := &tunnel.Profile{}
	runtime := &system.TunnelRuntimeInfo{
		AdapterRevision: tunnel.KernelAdapterRevision,
		Ready:           false,
	}
	engine := &Engine{config: &EngineConfig{
		TunnelProfile: profile,
		TunnelRuntime: runtime,
	}}

	engine.markKernelAWGRuntimeReady()

	assert.True(t, runtime.Ready, "accepted kernel profile should become ready")
}

func TestConfigurePeerTunnelStateRejectsFailedKernel(t *testing.T) {
	t.Setenv("NB_USE_NETSTACK_MODE", "false")
	configureErr := errors.New("kernel interface disappeared")
	runtime := &system.TunnelRuntimeInfo{Ready: true}
	engine := &Engine{
		config: &EngineConfig{
			TunnelProfile: &tunnel.Profile{},
			TunnelRuntime: runtime,
		},
		wgInterface: &failingHybridWGIface{err: configureErr},
	}

	err := engine.configurePeerTunnelState("peer", peerTunnelState{
		mode:            tunnel.ModeAmneziaWG2,
		profileRevision: 1,
	})

	assert.ErrorIs(t, err, configureErr)
	assert.False(t, runtime.Ready, "failed kernel mode update should clear readiness")
}

type failingHybridWGIface struct {
	WGIface
	err error
}

func (f *failingHybridWGIface) ConfigureTunnelProfile(*tunnel.Profile) error {
	return f.err
}

func (f *failingHybridWGIface) SetPeerTunnelMode(
	string,
	tunnel.Mode,
	uint64,
) error {
	return f.err
}
