package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	clienttunnel "github.com/netbirdio/netbird/client/iface/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

const (
	// HybridAWG2AdapterRevision identifies the reviewed wireguard-go fork.
	HybridAWG2AdapterRevision = "2ae1edae71cfa2d5a3265e3d8e316f0a5914944f"
	// HybridAWG3AdapterRevision identifies the reviewed AWG3-capable fork.
	HybridAWG3AdapterRevision = clienttunnel.AdapterRevision
	pairTransitionDelay       = 30 * time.Second
)

// PeerConfig is a server-computed tunnel decision for one remote peer.
type PeerConfig struct {
	Mode            proto.TunnelMode
	ProtocolVersion string
	ProfileRevision uint64
	TransitionID    string
	EffectiveAt     *timestamppb.Timestamp
}

// PlanPeerConfigs computes symmetric tunnel decisions for a receiving peer.
func PlanPeerConfigs(
	local *sharedtypes.ComponentPeer,
	remotes []*sharedtypes.ComponentPeer,
	settings *types.Settings,
	userPolicies map[string]sharedtypes.TunnelUserPolicyInfo,
	now time.Time,
) map[string]PeerConfig {
	if local == nil || settings == nil {
		return nil
	}

	configs := make(map[string]PeerConfig, len(remotes))
	for _, remote := range remotes {
		if remote == nil || remote.ID == local.ID {
			continue
		}
		configs[remote.ID] = planPeerPair(
			local,
			remote,
			settings,
			userPolicies,
			now,
		)
	}
	return configs
}

// ProfileForPeer returns the profile assigned to a Hybrid AWG-capable peer.
func ProfileForPeer(
	peer *sharedtypes.ComponentPeer,
	settings *types.Settings,
	now time.Time,
) *proto.TunnelProfile {
	if peer == nil ||
		settings == nil ||
		effectiveTunnelProfile(settings) == nil {
		return nil
	}
	profile := effectiveTunnelProfile(settings)
	protocolVersion := assignedProtocol(peer, profile)
	if protocolVersion == "" {
		return nil
	}
	parameters := slices.Clone(profile.Parameters)
	var headerProtectionKey []byte
	if protocolVersion == clienttunnel.ProtocolAmneziaWG3 {
		headerProtectionKey = slices.Clone(profile.HeaderProtectionKey)
	} else if profile.ProtocolVersion == clienttunnel.ProtocolAmneziaWG3 {
		decoded, err := clienttunnel.DecodeProfileWithHeaderKey(
			profile.ProtocolVersion,
			profile.Revision,
			profile.Parameters,
			profile.HeaderProtectionKey,
		)
		if err != nil {
			return nil
		}
		parameters, err = json.Marshal(decoded.AWG2)
		if err != nil {
			return nil
		}
	}
	return &proto.TunnelProfile{
		ProtocolVersion:     protocolVersion,
		Revision:            profile.Revision,
		Parameters:          parameters,
		ServerTime:          timestamppb.New(now),
		HeaderProtectionKey: headerProtectionKey,
	}
}

func planPeerPair(
	left,
	right *sharedtypes.ComponentPeer,
	settings *types.Settings,
	userPolicies map[string]sharedtypes.TunnelUserPolicyInfo,
	now time.Time,
) PeerConfig {
	accountPolicy := settings.TunnelPolicy
	if accountPolicy == "" {
		accountPolicy = AccountPolicyStandard
	}
	leftPolicy := userPolicy(left.UserID, userPolicies)
	rightPolicy := userPolicy(right.UserID, userPolicies)
	profile := effectiveTunnelProfile(settings)

	if settings.TunnelProfilePending != nil {
		if accountPolicy == types.TunnelAccountPolicyRequireAWG {
			return PeerConfig{Mode: proto.TunnelMode_TunnelModeBlocked}
		}
		return PeerConfig{Mode: proto.TunnelMode_TunnelModeStandard}
	}

	leftState := plannerPeerState(left, leftPolicy, profile)
	rightState := plannerPeerState(right, rightPolicy, profile)
	current := PairState{Mode: previousPairMode(left, right, profile, now)}
	decision := ResolvePair(accountPolicy, leftState, rightState, current)
	if decision.Blocked {
		return PeerConfig{Mode: proto.TunnelMode_TunnelModeBlocked}
	}
	if decision.Mode == proto.TunnelMode_TunnelModeAmneziaWG ||
		decision.Mode == proto.TunnelMode_TunnelModeAmneziaWG3 {
		return awgPeerConfig(
			left,
			right,
			settings,
			userPolicies,
			decision.Mode,
			decision.Pending,
		)
	}
	return standardPeerConfig(
		left,
		right,
		settings,
		userPolicies,
		current.Mode,
	)
}

func effectiveTunnelProfile(settings *types.Settings) *types.TunnelProfile {
	if settings == nil {
		return nil
	}
	if settings.TunnelProfilePending != nil {
		return settings.TunnelProfilePending
	}
	return settings.TunnelProfile
}

func plannerPeerState(
	peer *sharedtypes.ComponentPeer,
	policy UserPolicy,
	profile *types.TunnelProfile,
) PeerState {
	runtime := peer.TunnelRuntime
	protocolVersion := assignedProtocol(peer, profile)
	var profileRevision uint64
	if profile != nil {
		profileRevision = profile.Revision
	}
	ready := profile != nil &&
		protocolVersion != "" &&
		runtime.Ready &&
		!runtime.UpdatedAt.IsZero()
	return PeerState{
		SupportsHybridAWG2: peer.SupportsHybridAWG2,
		SupportsHybridAWG3: peer.SupportsHybridAWG3,
		Ready:              ready,
		AssignedProtocol:   protocolVersion,
		AssignedRevision:   profileRevision,
		ProtocolVersion:    runtime.ProtocolVersion,
		ProfileRevision:    runtime.ProfileRevision,
		AdapterCompatible: adapterSupportsProtocol(
			runtime.AdapterRevision,
			protocolVersion,
		),
		UserPolicy: policy,
	}
}

func previousPairMode(
	left,
	right *sharedtypes.ComponentPeer,
	profile *types.TunnelProfile,
	now time.Time,
) proto.TunnelMode {
	if profile == nil ||
		left.TunnelRuntime.LastReadyRevision != profile.Revision ||
		right.TunnelRuntime.LastReadyRevision != profile.Revision {
		return proto.TunnelMode_TunnelModeStandard
	}
	effectiveAt := maxTime(
		profile.UpdatedAt,
		left.TunnelRuntime.LastReadyAt,
		right.TunnelRuntime.LastReadyAt,
	).Add(pairTransitionDelay)
	if effectiveAt.After(now) {
		return proto.TunnelMode_TunnelModeStandard
	}
	return modeForReadyProtocols(
		left,
		right,
		left.TunnelRuntime.LastReadyProtocol,
		right.TunnelRuntime.LastReadyProtocol,
	)
}

func awgPeerConfig(
	left,
	right *sharedtypes.ComponentPeer,
	settings *types.Settings,
	userPolicies map[string]sharedtypes.TunnelUserPolicyInfo,
	mode proto.TunnelMode,
	pending bool,
) PeerConfig {
	profile := settings.TunnelProfile
	transitionDelay := pairTransitionDelay
	if settings.TunnelPolicy == types.TunnelAccountPolicyRequireAWG {
		transitionDelay = 0
	}
	effectiveAt := maxTime(
		profile.UpdatedAt,
		settings.TunnelPolicyUpdatedAt,
		userPolicyUpdatedAt(left.UserID, userPolicies),
		userPolicyUpdatedAt(right.UserID, userPolicies),
		left.TunnelRuntime.UpdatedAt,
		right.TunnelRuntime.UpdatedAt,
	).Add(transitionDelay)
	if pending {
		effectiveAt = maxTime(
			profile.UpdatedAt,
			left.TunnelRuntime.LastReadyAt,
			right.TunnelRuntime.LastReadyAt,
		).Add(transitionDelay)
	}
	return PeerConfig{
		Mode:            mode,
		ProtocolVersion: protocolForMode(mode),
		ProfileRevision: profile.Revision,
		TransitionID: transitionID(
			left,
			right,
			mode,
			profile.Revision,
			effectiveAt,
		),
		EffectiveAt: timestamppb.New(effectiveAt),
	}
}

func standardPeerConfig(
	left,
	right *sharedtypes.ComponentPeer,
	settings *types.Settings,
	userPolicies map[string]sharedtypes.TunnelUserPolicyInfo,
	currentMode proto.TunnelMode,
) PeerConfig {
	if settings.TunnelProfile == nil {
		return PeerConfig{Mode: proto.TunnelMode_TunnelModeStandard}
	}
	if highestCommonMode(plannerPeerState(left, UserPolicyInherit, settings.TunnelProfile),
		plannerPeerState(right, UserPolicyInherit, settings.TunnelProfile)) ==
		proto.TunnelMode_TunnelModeStandard {
		return PeerConfig{Mode: proto.TunnelMode_TunnelModeStandard}
	}
	if currentMode == proto.TunnelMode_TunnelModeStandard {
		return PeerConfig{Mode: proto.TunnelMode_TunnelModeStandard}
	}
	anchor := maxTime(
		settings.TunnelPolicyUpdatedAt,
		userPolicyUpdatedAt(left.UserID, userPolicies),
		userPolicyUpdatedAt(right.UserID, userPolicies),
	)
	if anchor.IsZero() {
		return PeerConfig{Mode: proto.TunnelMode_TunnelModeStandard}
	}
	effectiveAt := anchor.Add(pairTransitionDelay)
	return PeerConfig{
		Mode:            proto.TunnelMode_TunnelModeStandard,
		ProtocolVersion: protocolForMode(currentMode),
		ProfileRevision: settings.TunnelProfile.Revision,
		TransitionID: transitionID(
			left,
			right,
			proto.TunnelMode_TunnelModeStandard,
			0,
			effectiveAt,
		),
		EffectiveAt: timestamppb.New(effectiveAt),
	}
}

func assignedProtocol(
	peer *sharedtypes.ComponentPeer,
	profile *types.TunnelProfile,
) string {
	if peer == nil || profile == nil {
		return ""
	}
	if profile.ProtocolVersion == clienttunnel.ProtocolAmneziaWG3 &&
		peer.SupportsHybridAWG3 {
		return clienttunnel.ProtocolAmneziaWG3
	}
	if peer.SupportsHybridAWG2 {
		return clienttunnel.ProtocolAmneziaWG2
	}
	return ""
}

func adapterSupportsProtocol(adapterRevision, protocolVersion string) bool {
	switch protocolVersion {
	case clienttunnel.ProtocolAmneziaWG3:
		return adapterRevision == HybridAWG3AdapterRevision
	case clienttunnel.ProtocolAmneziaWG2:
		return adapterRevision == HybridAWG2AdapterRevision ||
			adapterRevision == HybridAWG3AdapterRevision
	default:
		return false
	}
}

func modeForReadyProtocols(
	left,
	right *sharedtypes.ComponentPeer,
	leftProtocol,
	rightProtocol string,
) proto.TunnelMode {
	if left.SupportsHybridAWG3 && right.SupportsHybridAWG3 &&
		leftProtocol == clienttunnel.ProtocolAmneziaWG3 &&
		rightProtocol == clienttunnel.ProtocolAmneziaWG3 {
		return proto.TunnelMode_TunnelModeAmneziaWG3
	}
	if left.SupportsHybridAWG2 && right.SupportsHybridAWG2 &&
		supportsAWG2Profile(leftProtocol) && supportsAWG2Profile(rightProtocol) {
		return proto.TunnelMode_TunnelModeAmneziaWG
	}
	return proto.TunnelMode_TunnelModeStandard
}

func protocolForMode(mode proto.TunnelMode) string {
	switch mode {
	case proto.TunnelMode_TunnelModeAmneziaWG:
		return clienttunnel.ProtocolAmneziaWG2
	case proto.TunnelMode_TunnelModeAmneziaWG3:
		return clienttunnel.ProtocolAmneziaWG3
	default:
		return ""
	}
}

func userPolicy(
	userID string,
	policies map[string]sharedtypes.TunnelUserPolicyInfo,
) UserPolicy {
	policy := UserPolicy(policies[userID].Policy)
	switch policy {
	case UserPolicyPreferAWG, UserPolicyStandardOnly:
		return policy
	default:
		return UserPolicyInherit
	}
}

func userPolicyUpdatedAt(
	userID string,
	policies map[string]sharedtypes.TunnelUserPolicyInfo,
) time.Time {
	return policies[userID].UpdatedAt
}

func transitionID(
	left,
	right *sharedtypes.ComponentPeer,
	mode proto.TunnelMode,
	revision uint64,
	effectiveAt time.Time,
) string {
	pair := []string{peerIdentity(left), peerIdentity(right)}
	slices.Sort(pair)
	sum := sha256.Sum256([]byte(fmt.Sprintf(
		"%s\x00%s\x00%d\x00%d\x00%d",
		pair[0],
		pair[1],
		mode,
		revision,
		effectiveAt.UnixNano(),
	)))
	return hex.EncodeToString(sum[:16])
}

func peerIdentity(peer *sharedtypes.ComponentPeer) string {
	if peer.ID != "" {
		return peer.ID
	}
	return peer.Key
}

func maxTime(values ...time.Time) time.Time {
	var latest time.Time
	for _, value := range values {
		if value.After(latest) {
			latest = value
		}
	}
	return latest
}
