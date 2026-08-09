//go:build linux && !android && hybrid_awg

package system

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/device"
)

var kernelAWGProbe = newKernelAWGProbeCache(device.ProbeAWGKernel)

type kernelAWGProbeCache struct {
	mu        sync.Mutex
	probe     func() error
	checked   bool
	available bool
}

func newKernelAWGProbeCache(probe func() error) *kernelAWGProbeCache {
	return &kernelAWGProbeCache{probe: probe}
}

func (c *kernelAWGProbeCache) isAvailable() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.checked {
		return c.available
	}
	c.checked = true
	if err := c.probe(); err != nil {
		log.Debugf("AmneziaWG kernel backend is unavailable: %v", err)
		return false
	}
	c.available = true
	return c.available
}

func (c *kernelAWGProbeCache) invalidate() {
	c.mu.Lock()
	c.checked = false
	c.available = false
	c.mu.Unlock()
}

func kernelAWGAvailable() bool {
	return kernelAWGProbe.isAvailable()
}
