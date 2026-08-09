package client

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestPeerCapabilitiesReportsKernelAWGAvailability(t *testing.T) {
	withoutKernel := peerCapabilities(system.Info{})
	withKernel := peerCapabilities(system.Info{KernelAWGAvailable: true})

	assert.NotContains(
		t,
		withoutKernel,
		proto.PeerCapability_PeerCapabilityKernelAmneziaWG,
	)
	assert.Contains(
		t,
		withKernel,
		proto.PeerCapability_PeerCapabilityKernelAmneziaWG,
	)
}
