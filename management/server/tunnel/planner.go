package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

const (
	// HybridAWG2AdapterRevision identifies the reviewed wireguard-go fork.
	HybridAWG2AdapterRevision = "2ae1edae71cfa2d5a3265e3d8e316f0a5914944f"
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
		!peer.SupportsHybridAWG2 ||
		settings == nil ||
		settings.TunnelProfile == nil {
		return nil
	}
	profile := settings.TunnelProfile
	return &proto.TunnelProfile{
		ProtocolVersion: profile.ProtocolVersion,
		Revision:        profile.Revision,
		Parameters:      slices.Clone(profile.Parameters),
		ServerTime:      timestamppb.New(now),
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
	profile := settings.TunnelProfile

	leftState := plannerPeerState(left, leftPolicy, profile)
	rightState := plannerPeerState(right, rightPolicy, profile)
	current := PairState{Mode: previousPairMode(left, right, profile, now)}
	decision := ResolvePair(accountPolicy, leftState, rightState, current)
	if decision.Blocked {
		return PeerConfig{Mode: proto.TunnelMode_TunnelModeBlocked}
	}
	if decision.Mode == proto.TunnelMode_TunnelModeAmneziaWG {
		return awgPeerConfig(
			left,
			right,
			settings,
			userPolicies,
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

func plannerPeerState(
	peer *sharedtypes.ComponentPeer,
	policy UserPolicy,
	profile *types.TunnelProfile,
) PeerState {
	runtime := peer.TunnelRuntime
	ready := profile != nil &&
		runtime.Ready &&
		!runtime.UpdatedAt.IsZero() &&
		runtime.ProtocolVersion == profile.ProtocolVersion &&
		runtime.ProfileRevision == profile.Revision &&
		runtime.AdapterRevision == HybridAWG2AdapterRevision
	return PeerState{
		SupportsHybridAWG2: peer.SupportsHybridAWG2,
		Ready:              ready,
		ProtocolVersion:    runtime.ProtocolVersion,
		ProfileRevision:    runtime.ProfileRevision,
		UserPolicy:         policy,
	}
}

func previousPairMode(
	left,
	right *sharedtypes.ComponentPeer,
	profile *types.TunnelProfile,
	now time.Time,
) proto.TunnelMode {
	if profile == nil ||
		left.TunnelRuntime.LastReadyProtocol != profile.ProtocolVersion ||
		right.TunnelRuntime.LastReadyProtocol != profile.ProtocolVersion ||
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
	return proto.TunnelMode_TunnelModeAmneziaWG
}

func awgPeerConfig(
	left,
	right *sharedtypes.ComponentPeer,
	settings *types.Settings,
	userPolicies map[string]sharedtypes.TunnelUserPolicyInfo,
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
		Mode:            proto.TunnelMode_TunnelModeAmneziaWG,
		ProtocolVersion: profile.ProtocolVersion,
		ProfileRevision: profile.Revision,
		TransitionID: transitionID(
			left,
			right,
			proto.TunnelMode_TunnelModeAmneziaWG,
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
	if !left.SupportsHybridAWG2 || !right.SupportsHybridAWG2 {
		return PeerConfig{Mode: proto.TunnelMode_TunnelModeStandard}
	}
	if currentMode != proto.TunnelMode_TunnelModeAmneziaWG {
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
		Mode: proto.TunnelMode_TunnelModeStandard,
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
