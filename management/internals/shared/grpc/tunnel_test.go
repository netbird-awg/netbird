package grpc

import (
	"testing"

	managementtunnel "github.com/netbirdio/netbird/management/server/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/proto"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

func TestFilterBlockedRemoteConfigs(t *testing.T) {
	allowed := &proto.RemotePeerConfig{WgPubKey: "allowed"}
	blocked := &proto.RemotePeerConfig{
		WgPubKey:   "blocked",
		TunnelMode: proto.TunnelMode_TunnelModeBlocked,
	}

	filtered := filterBlockedRemoteConfigs(
		[]*proto.RemotePeerConfig{allowed, blocked, nil},
	)

	if len(filtered) != 1 || filtered[0] != allowed {
		t.Fatalf("blocked remote config was not removed: %+v", filtered)
	}
}

func TestFilterBlockedComponentsDoesNotMutateSource(t *testing.T) {
	allowed := &sharedtypes.ComponentPeer{ID: "allowed"}
	blocked := &sharedtypes.ComponentPeer{ID: "blocked"}
	components := &types.NetworkMapComponents{
		Peers: map[string]*sharedtypes.ComponentPeer{
			allowed.ID: allowed,
			blocked.ID: blocked,
		},
		RouterPeers: map[string]*sharedtypes.ComponentPeer{
			blocked.ID: blocked,
		},
		Routes: []*route.Route{
			{ID: "allowed-route", Peer: allowed.ID},
			{ID: "blocked-route", Peer: blocked.ID},
		},
		RoutersMap: map[string]map[string]*sharedtypes.ComponentRouter{
			"network": {
				allowed.ID: {},
				blocked.ID: {},
			},
		},
	}
	configs := map[string]managementtunnel.PeerConfig{
		blocked.ID: {Mode: proto.TunnelMode_TunnelModeBlocked},
	}

	filtered := filterBlockedComponents(components, configs)

	if _, ok := filtered.Peers[blocked.ID]; ok {
		t.Fatal("blocked peer remained in filtered components")
	}
	if _, ok := filtered.RouterPeers[blocked.ID]; ok {
		t.Fatal("blocked router peer remained in filtered components")
	}
	if len(filtered.Routes) != 1 || filtered.Routes[0].Peer != allowed.ID {
		t.Fatalf("blocked route remained: %+v", filtered.Routes)
	}
	if _, ok := filtered.RoutersMap["network"][blocked.ID]; ok {
		t.Fatal("blocked network router remained")
	}
	if _, ok := components.Peers[blocked.ID]; !ok {
		t.Fatal("source peer map was mutated")
	}
	if len(components.Routes) != 2 {
		t.Fatal("source route list was mutated")
	}
}

func TestToProxyPatchFiltersBlockedPeersAndRoutes(t *testing.T) {
	blocked := &sharedtypes.ComponentPeer{
		ID:  "blocked",
		Key: "blocked-key",
	}
	networkMap := &types.NetworkMap{
		Peers: []*sharedtypes.ComponentPeer{blocked},
		Routes: []*route.Route{
			{ID: "blocked-route", Peer: blocked.ID},
		},
	}
	configs := map[string]managementtunnel.PeerConfig{
		blocked.ID: {Mode: proto.TunnelMode_TunnelModeBlocked},
	}

	patch := toProxyPatch(
		networkMap,
		"netbird.test",
		false,
		false,
		configs,
	)

	if patch == nil {
		t.Fatal("non-empty proxy patch was omitted")
	}
	if len(patch.Peers) != 0 || len(patch.Routes) != 0 {
		t.Fatalf("blocked proxy data remained: %+v", patch)
	}
}
