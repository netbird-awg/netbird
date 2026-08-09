//go:build linux && !android

package device

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/client/iface/configurer"
)

func TestProbeAWGKernelRequiresModule(t *testing.T) {
	ops := awgKernelProbeOps{
		moduleLoaded: func() bool { return false },
	}

	err := probeAWGKernel("nbawgprobe", ops)

	require.ErrorIs(t, err, configurer.ErrAWGKernelUnavailable)
}

func TestProbeAWGKernelRequiresPerPeerTransport(t *testing.T) {
	deleted := false
	ops := successfulAWGKernelProbeOps(t, &deleted)
	ops.queryCapabilities = func(string) (configurer.AWGKernelCapabilities, error) {
		return 0, nil
	}

	err := probeAWGKernel("nbawgprobe", ops)

	require.ErrorIs(t, err, configurer.ErrAWGKernelPerPeerModeUnavailable)
	assert.True(t, deleted, "probe link should be deleted")
}

func TestProbeAWGKernelJoinsQueryAndCleanupErrors(t *testing.T) {
	queryErr := errors.New("query failed")
	deleteErr := errors.New("delete failed")
	ops := successfulAWGKernelProbeOps(t, nil)
	ops.queryCapabilities = func(string) (configurer.AWGKernelCapabilities, error) {
		return 0, queryErr
	}
	ops.deleteLink = func(netlink.Link) error { return deleteErr }

	err := probeAWGKernel("nbawgprobe", ops)

	require.ErrorIs(t, err, queryErr)
	require.ErrorIs(t, err, deleteErr)
}

func TestProbeAWGKernelAcceptsCompatibleBackend(t *testing.T) {
	deleted := false
	ops := successfulAWGKernelProbeOps(t, &deleted)

	err := probeAWGKernel("nbawgprobe", ops)

	require.NoError(t, err)
	assert.True(t, deleted, "probe link should be deleted")
}

func successfulAWGKernelProbeOps(t *testing.T, deleted *bool) awgKernelProbeOps {
	t.Helper()
	return awgKernelProbeOps{
		moduleLoaded: func() bool { return true },
		addLink: func(link netlink.Link) error {
			assert.Equal(t, "amneziawg", link.Type())
			return nil
		},
		deleteLink: func(netlink.Link) error {
			if deleted != nil {
				*deleted = true
			}
			return nil
		},
		queryCapabilities: func(string) (configurer.AWGKernelCapabilities, error) {
			return 1, nil
		},
	}
}
