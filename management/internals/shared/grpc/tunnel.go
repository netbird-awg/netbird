package grpc

import (
	"maps"
	"time"

	managementtunnel "github.com/netbirdio/netbird/management/server/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/proto"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

func planTunnelConfigs(
	local *sharedtypes.ComponentPeer,
	remotes []*sharedtypes.ComponentPeer,
	settings *types.Settings,
	userPolicies map[string]sharedtypes.TunnelUserPolicyInfo,
	now time.Time,
) map[string]managementtunnel.PeerConfig {
	return managementtunnel.PlanPeerConfigs(
		local,
		remotes,
		settings,
		userPolicies,
		now,
	)
}

func toEnvelopeTunnelConfigs(
	configs map[string]managementtunnel.PeerConfig,
) map[string]PeerTunnelConfig {
	result := make(map[string]PeerTunnelConfig, len(configs))
	for peerID, config := range configs {
		result[peerID] = PeerTunnelConfig{
			Mode:            config.Mode,
			ProtocolVersion: config.ProtocolVersion,
			ProfileRevision: config.ProfileRevision,
			TransitionID:    config.TransitionID,
			EffectiveAt:     config.EffectiveAt,
		}
	}
	return result
}

func applyTunnelConfigs(
	remoteConfigs []*proto.RemotePeerConfig,
	remotes []*sharedtypes.ComponentPeer,
	configs map[string]managementtunnel.PeerConfig,
) {
	configByKey := make(map[string]managementtunnel.PeerConfig, len(remotes))
	for _, remote := range remotes {
		if remote == nil {
			continue
		}
		config, ok := configs[remote.ID]
		if ok {
			configByKey[remote.Key] = config
		}
	}
	for _, remote := range remoteConfigs {
		if remote == nil {
			continue
		}
		config, ok := configByKey[remote.GetWgPubKey()]
		if !ok {
			continue
		}
		remote.TunnelMode = config.Mode
		remote.TunnelProtocolVersion = config.ProtocolVersion
		remote.TunnelProfileRevision = config.ProfileRevision
		remote.TunnelTransitionId = config.TransitionID
		remote.TunnelEffectiveAt = config.EffectiveAt
	}
}

func filterBlockedRemoteConfigs(
	remotes []*proto.RemotePeerConfig,
) []*proto.RemotePeerConfig {
	filtered := remotes[:0]
	for _, remote := range remotes {
		if remote == nil ||
			remote.GetTunnelMode() == proto.TunnelMode_TunnelModeBlocked {
			continue
		}
		filtered = append(filtered, remote)
	}
	return filtered
}

func filterBlockedComponents(
	components *types.NetworkMapComponents,
	configs map[string]managementtunnel.PeerConfig,
) *types.NetworkMapComponents {
	if components == nil {
		return nil
	}
	blocked := blockedPeerIDs(configs)
	if len(blocked) == 0 {
		return components
	}

	filtered := copyComponentsForTunnelFiltering(components)
	for peerID := range blocked {
		delete(filtered.Peers, peerID)
		delete(filtered.RouterPeers, peerID)
	}
	filtered.Routes = filterBlockedRoutes(components.Routes, blocked)
	filtered.RoutersMap = filterBlockedRouters(components.RoutersMap, blocked)
	return filtered
}

func copyComponentsForTunnelFiltering(
	components *types.NetworkMapComponents,
) *types.NetworkMapComponents {
	return &types.NetworkMapComponents{
		PeerID:                        components.PeerID,
		Network:                       components.Network,
		AccountSettings:               components.AccountSettings,
		DNSSettings:                   components.DNSSettings,
		CustomZoneDomain:              components.CustomZoneDomain,
		Peers:                         maps.Clone(components.Peers),
		Groups:                        components.Groups,
		Policies:                      components.Policies,
		Routes:                        components.Routes,
		NameServerGroups:              components.NameServerGroups,
		AllDNSRecords:                 components.AllDNSRecords,
		AccountZones:                  components.AccountZones,
		ResourcePoliciesMap:           components.ResourcePoliciesMap,
		RoutersMap:                    components.RoutersMap,
		NetworkResources:              components.NetworkResources,
		GroupIDToUserIDs:              components.GroupIDToUserIDs,
		AllowedUserIDs:                components.AllowedUserIDs,
		UserTunnelPolicies:            components.UserTunnelPolicies,
		PostureFailedPeers:            components.PostureFailedPeers,
		RouterPeers:                   maps.Clone(components.RouterPeers),
		NetworkXIDToPublicID:          components.NetworkXIDToPublicID,
		PostureCheckXIDToPublicID:     components.PostureCheckXIDToPublicID,
		ForceRoutingPeerDNSResolution: components.ForceRoutingPeerDNSResolution,
	}
}

func blockedPeerIDs(
	configs map[string]managementtunnel.PeerConfig,
) map[string]struct{} {
	blocked := make(map[string]struct{})
	for peerID, config := range configs {
		if config.Mode == proto.TunnelMode_TunnelModeBlocked {
			blocked[peerID] = struct{}{}
		}
	}
	return blocked
}

func filterBlockedRoutes(
	routes []*route.Route,
	blocked map[string]struct{},
) []*route.Route {
	if len(blocked) == 0 {
		return routes
	}
	filtered := make([]*route.Route, 0, len(routes))
	for _, networkRoute := range routes {
		if networkRoute == nil {
			continue
		}
		if _, ok := blocked[networkRoute.Peer]; ok {
			continue
		}
		filtered = append(filtered, networkRoute)
	}
	return filtered
}

func filterBlockedRouters(
	routers map[string]map[string]*sharedtypes.ComponentRouter,
	blocked map[string]struct{},
) map[string]map[string]*sharedtypes.ComponentRouter {
	filtered := make(map[string]map[string]*sharedtypes.ComponentRouter, len(routers))
	for networkID, networkRouters := range routers {
		kept := maps.Clone(networkRouters)
		for peerID := range blocked {
			delete(kept, peerID)
		}
		filtered[networkID] = kept
	}
	return filtered
}

func appendComponentPeers(
	first,
	second map[string]*sharedtypes.ComponentPeer,
) []*sharedtypes.ComponentPeer {
	seen := make(map[string]struct{}, len(first)+len(second))
	result := make([]*sharedtypes.ComponentPeer, 0, len(first)+len(second))
	for _, peers := range []map[string]*sharedtypes.ComponentPeer{first, second} {
		for _, peer := range peers {
			if peer == nil {
				continue
			}
			if _, ok := seen[peer.ID]; ok {
				continue
			}
			seen[peer.ID] = struct{}{}
			result = append(result, peer)
		}
	}
	return result
}
