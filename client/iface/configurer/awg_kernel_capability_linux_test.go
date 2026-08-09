//go:build linux && !android

package configurer

import (
	"testing"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/stretchr/testify/require"
)

func TestParseAWGKernelCapabilities(t *testing.T) {
	attributes, err := netlink.MarshalAttributes([]netlink.Attribute{
		{
			Type: awgKernelDeviceIfName,
			Data: nlenc.Bytes("wt0"),
		},
		{
			Type: awgKernelDeviceCapabilities,
			Data: nlenc.Uint64Bytes(uint64(awgKernelCapabilityPerPeerTransportMode)),
		},
	})
	require.NoError(t, err)

	capabilities, err := parseAWGKernelCapabilities([]genetlink.Message{{
		Data: attributes,
	}})
	require.NoError(t, err)
	require.True(t, capabilities.SupportsPerPeerTransportMode())
}

func TestParseAWGKernelCapabilitiesDefaultsToUnsupported(t *testing.T) {
	attributes, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: awgKernelDeviceIfName,
		Data: nlenc.Bytes("wt0"),
	}})
	require.NoError(t, err)

	capabilities, err := parseAWGKernelCapabilities([]genetlink.Message{{
		Data: attributes,
	}})
	require.NoError(t, err)
	require.False(t, capabilities.SupportsPerPeerTransportMode())
}

func TestParseAWGKernelCapabilitiesRejectsMalformedAttribute(t *testing.T) {
	_, err := parseAWGKernelCapabilities([]genetlink.Message{{
		Data: []byte{3, 0, 0, 0},
	}})
	require.Error(t, err)
}
