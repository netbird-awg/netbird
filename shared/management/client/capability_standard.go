//go:build !hybrid_awg

package client

import "github.com/netbirdio/netbird/shared/management/proto"

func hybridAWGCapabilities() []proto.PeerCapability {
	return nil
}
