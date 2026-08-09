//go:build linux && !android

package device

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/client/iface/configurer"
)

const awgKernelProbeNamePrefix = "nbawg"

type awgKernelProbeOps struct {
	moduleLoaded      func() bool
	addLink           func(netlink.Link) error
	deleteLink        func(netlink.Link) error
	queryCapabilities func(string) (configurer.AWGKernelCapabilities, error)
}

// ProbeAWGKernel verifies that the Linux AmneziaWG backend supports NetBird's
// per-peer transport mode.
func ProbeAWGKernel() error {
	name, err := newAWGKernelProbeName()
	if err != nil {
		return fmt.Errorf("generate AmneziaWG probe name: %w", err)
	}
	return probeAWGKernel(name, awgKernelProbeOps{
		moduleLoaded:      AmneziaWGModuleIsLoaded,
		addLink:           netlink.LinkAdd,
		deleteLink:        netlink.LinkDel,
		queryCapabilities: configurer.QueryAWGKernelCapabilities,
	})
}

func newAWGKernelProbeName() (string, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return awgKernelProbeNamePrefix + hex.EncodeToString(suffix[:]), nil
}

func probeAWGKernel(name string, ops awgKernelProbeOps) error {
	if !ops.moduleLoaded() {
		return fmt.Errorf(
			"%w: module or link kind is unavailable",
			configurer.ErrAWGKernelUnavailable,
		)
	}

	link := newAWGLink(name)
	if err := ops.addLink(link); err != nil {
		return fmt.Errorf("create AmneziaWG probe link: %w", err)
	}

	capabilities, queryErr := ops.queryCapabilities(name)
	deleteErr := ops.deleteLink(link)
	if queryErr != nil {
		queryErr = fmt.Errorf("query AmneziaWG probe capabilities: %w", queryErr)
	}
	if deleteErr != nil {
		deleteErr = fmt.Errorf("delete AmneziaWG probe link: %w", deleteErr)
	}
	if err := errors.Join(queryErr, deleteErr); err != nil {
		return err
	}
	if !capabilities.SupportsPerPeerTransportMode() {
		return configurer.ErrAWGKernelPerPeerModeUnavailable
	}
	return nil
}
