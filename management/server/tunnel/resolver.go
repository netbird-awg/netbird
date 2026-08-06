// Package tunnel resolves symmetric peer tunnel modes.
package tunnel

import (
	"fmt"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// AccountPolicy controls whether an account permits or requires AWG.
type AccountPolicy = types.TunnelAccountPolicy

const (
	AccountPolicyStandard   = types.TunnelAccountPolicyStandard
	AccountPolicyPreferAWG  = types.TunnelAccountPolicyPreferAWG
	AccountPolicyRequireAWG = types.TunnelAccountPolicyRequireAWG
)

// UserPolicy refines the account policy for peers owned by a user.
type UserPolicy = types.TunnelUserPolicy

const (
	UserPolicyInherit      = types.TunnelUserPolicyInherit
	UserPolicyPreferAWG    = types.TunnelUserPolicyPreferAWG
	UserPolicyStandardOnly = types.TunnelUserPolicyStandardOnly
)

// PeerState contains the trusted capability and readiness inputs for a peer.
type PeerState struct {
	SupportsHybridAWG2 bool
	Ready              bool
	ProtocolVersion    string
	ProfileRevision    uint64
	UserPolicy         UserPolicy
}

// PairState is the current symmetric state of a peer pair.
type PairState struct {
	Mode proto.TunnelMode
}

// Decision is the next symmetric state selected for both peer directions.
type Decision struct {
	Mode    proto.TunnelMode
	Pending bool
	Blocked bool
	Reason  string
}

// ResolvePair selects one symmetric mode from trusted Management state.
func ResolvePair(
	accountPolicy AccountPolicy,
	left,
	right PeerState,
	current PairState,
) Decision {
	switch accountPolicy {
	case AccountPolicyStandard:
		if left.UserPolicy == UserPolicyPreferAWG ||
			right.UserPolicy == UserPolicyPreferAWG {
			return resolvePreferAWG(left, right, current)
		}
		return standardDecision()
	case AccountPolicyPreferAWG:
		return resolvePreferAWG(left, right, current)
	case AccountPolicyRequireAWG:
		return resolveRequireAWG(left, right)
	default:
		return blockedDecision(fmt.Sprintf("unknown account policy %q", accountPolicy))
	}
}

func resolvePreferAWG(left, right PeerState, current PairState) Decision {
	if left.UserPolicy == UserPolicyStandardOnly ||
		right.UserPolicy == UserPolicyStandardOnly {
		return standardDecision()
	}
	if !left.SupportsHybridAWG2 || !right.SupportsHybridAWG2 {
		return standardDecision()
	}
	if reason := reportedMismatchReason(left, right); reason != "" {
		return blockedDecision(reason)
	}
	if !left.Ready || !right.Ready {
		return Decision{
			Mode:    current.Mode,
			Pending: true,
			Reason:  "both Hybrid AWG peers are not ready",
		}
	}
	if reason := incompatibleReason(left, right); reason != "" {
		return blockedDecision(reason)
	}
	return Decision{Mode: proto.TunnelMode_TunnelModeAmneziaWG}
}

func resolveRequireAWG(left, right PeerState) Decision {
	if left.UserPolicy == UserPolicyStandardOnly ||
		right.UserPolicy == UserPolicyStandardOnly {
		return blockedDecision("standard-only user policy conflicts with required AWG")
	}
	if !left.SupportsHybridAWG2 || !right.SupportsHybridAWG2 {
		return blockedDecision("required AWG peer lacks Hybrid AWG capability")
	}
	if !left.Ready || !right.Ready {
		return blockedDecision("required AWG peer is not ready")
	}
	if reason := incompatibleReason(left, right); reason != "" {
		return blockedDecision(reason)
	}
	return Decision{Mode: proto.TunnelMode_TunnelModeAmneziaWG}
}

func incompatibleReason(left, right PeerState) string {
	if left.ProtocolVersion == "" || right.ProtocolVersion == "" {
		return "AWG protocol version is missing"
	}
	if left.ProtocolVersion != right.ProtocolVersion {
		return "AWG protocol versions differ"
	}
	if left.ProfileRevision == 0 || right.ProfileRevision == 0 {
		return "AWG profile revision is missing"
	}
	if left.ProfileRevision != right.ProfileRevision {
		return "AWG profile revisions differ"
	}
	return ""
}

func reportedMismatchReason(left, right PeerState) string {
	if left.ProtocolVersion != "" &&
		right.ProtocolVersion != "" &&
		left.ProtocolVersion != right.ProtocolVersion {
		return "AWG protocol versions differ"
	}
	if left.ProfileRevision != 0 &&
		right.ProfileRevision != 0 &&
		left.ProfileRevision != right.ProfileRevision {
		return "AWG profile revisions differ"
	}
	return ""
}

func standardDecision() Decision {
	return Decision{Mode: proto.TunnelMode_TunnelModeStandard}
}

func blockedDecision(reason string) Decision {
	return Decision{
		Mode:    proto.TunnelMode_TunnelModeStandard,
		Blocked: true,
		Reason:  reason,
	}
}
