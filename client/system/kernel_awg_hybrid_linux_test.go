//go:build linux && !android && hybrid_awg

package system

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKernelAWGProbeCacheCachesAvailability(t *testing.T) {
	calls := 0
	cache := newKernelAWGProbeCache(func() error {
		calls++
		return nil
	})

	assert.True(t, cache.isAvailable(), "successful probe should be available")
	assert.True(t, cache.isAvailable(), "cached probe should remain available")
	assert.Equal(t, 1, calls, "probe should run once")
}

func TestKernelAWGProbeCacheCachesFailure(t *testing.T) {
	calls := 0
	cache := newKernelAWGProbeCache(func() error {
		calls++
		return errors.New("unavailable")
	})

	assert.False(t, cache.isAvailable(), "failed probe should be unavailable")
	assert.False(t, cache.isAvailable(), "failed probe should remain cached")
	assert.Equal(t, 1, calls, "probe should run once")
}

func TestKernelAWGProbeCacheCanBeInvalidated(t *testing.T) {
	calls := 0
	cache := newKernelAWGProbeCache(func() error {
		calls++
		return nil
	})

	assert.True(t, cache.isAvailable(), "successful probe should be available")
	cache.invalidate()
	assert.True(t, cache.isAvailable(), "probe should recover after invalidation")
	assert.Equal(t, 2, calls, "invalidated probe should run again")
}

func TestKernelAWGProbeCacheCanBeMarkedUnavailable(t *testing.T) {
	calls := 0
	cache := newKernelAWGProbeCache(func() error {
		calls++
		return nil
	})

	assert.True(t, cache.isAvailable(), "successful probe should be available")
	cache.markUnavailable()
	assert.False(t, cache.isAvailable(), "rejected backend should stay unavailable")
	assert.Equal(t, 1, calls, "rejected backend should not be probed again")
}

func TestKernelAWGUnavailableInNetstackMode(t *testing.T) {
	t.Setenv("NB_USE_NETSTACK_MODE", "true")

	assert.False(t, kernelAWGAvailable(), "netstack must not advertise kernel AWG")
}
