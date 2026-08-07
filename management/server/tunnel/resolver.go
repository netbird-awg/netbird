// Package tunnel resolves symmetric peer tunnel modes.
package tunnel

import (
	"fmt"

	clienttunnel "github.com/netbirdio/netbird/client/iface/tunnel"
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
	SupportsHybridAWG3 bool
	Ready              bool
	AssignedProtocol   string
	AssignedRevision   uint64
	ProtocolVersion    string
	ProfileRevision    uint64
	AdapterCompatible  bool
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
	mode := highestCommonMode(left, right)
	if mode == proto.TunnelMode_TunnelModeStandard {
		return standardDecision()
	}
	if !left.Ready || !right.Ready {
		return Decision{
			Mode:    current.Mode,
			Pending: true,
			Reason:  "both Hybrid AWG peers are not ready",
		}
	}
	if reason := configurationMismatchReason(left, right); reason != "" {
		if current.Mode == proto.TunnelMode_TunnelModeStandard {
			return Decision{
				Mode:    current.Mode,
				Pending: true,
				Reason:  reason,
			}
		}
		return blockedDecision(reason)
	}
	if reason := incompatibleReason(mode, left, right); reason != "" {
		return blockedDecision(reason)
	}
	return Decision{Mode: mode}
}

func resolveRequireAWG(left, right PeerState) Decision {
	if left.UserPolicy == UserPolicyStandardOnly ||
		right.UserPolicy == UserPolicyStandardOnly {
		return blockedDecision("standard-only user policy conflicts with required AWG")
	}
	mode := highestCommonMode(left, right)
	if mode == proto.TunnelMode_TunnelModeStandard {
		return blockedDecision("required AWG peer lacks Hybrid AWG capability")
	}
	if !left.Ready || !right.Ready {
		return blockedDecision("required AWG peer is not ready")
	}
	if reason := configurationMismatchReason(left, right); reason != "" {
		return blockedDecision(reason)
	}
	if reason := incompatibleReason(mode, left, right); reason != "" {
		return blockedDecision(reason)
	}
	return Decision{Mode: mode}
}

func highestCommonMode(left, right PeerState) proto.TunnelMode {
	if left.SupportsHybridAWG3 && right.SupportsHybridAWG3 &&
		left.AssignedProtocol == clienttunnel.ProtocolAmneziaWG3 &&
		right.AssignedProtocol == clienttunnel.ProtocolAmneziaWG3 {
		return proto.TunnelMode_TunnelModeAmneziaWG3
	}
	if left.SupportsHybridAWG2 && right.SupportsHybridAWG2 &&
		supportsAWG2Profile(left.AssignedProtocol) &&
		supportsAWG2Profile(right.AssignedProtocol) {
		return proto.TunnelMode_TunnelModeAmneziaWG
	}
	return proto.TunnelMode_TunnelModeStandard
}

func incompatibleReason(mode proto.TunnelMode, left, right PeerState) string {
	if left.ProtocolVersion == "" || right.ProtocolVersion == "" {
		return "AWG protocol version is missing"
	}
	switch mode {
	case proto.TunnelMode_TunnelModeAmneziaWG3:
		if left.ProtocolVersion != clienttunnel.ProtocolAmneziaWG3 ||
			right.ProtocolVersion != clienttunnel.ProtocolAmneziaWG3 {
			return "AWG3 mode requires two AWG3 profiles"
		}
	case proto.TunnelMode_TunnelModeAmneziaWG:
		if !supportsAWG2Profile(left.ProtocolVersion) ||
			!supportsAWG2Profile(right.ProtocolVersion) {
			return "AWG2 mode requires AWG2-compatible profiles"
		}
	default:
		return "unsupported AWG tunnel mode"
	}
	if left.ProfileRevision == 0 || right.ProfileRevision == 0 {
		return "AWG profile revision is missing"
	}
	if left.ProfileRevision != right.ProfileRevision {
		return "AWG profile revisions differ"
	}
	return ""
}

func configurationMismatchReason(left, right PeerState) string {
	for _, peer := range []PeerState{left, right} {
		if !peer.AdapterCompatible {
			return "AWG adapter revision is incompatible"
		}
		if peer.ProtocolVersion != peer.AssignedProtocol {
			return "AWG reported protocol does not match its assigned profile"
		}
		if peer.AssignedRevision == 0 ||
			peer.ProfileRevision != peer.AssignedRevision {
			return "AWG reported revision does not match its assigned profile"
		}
	}
	return ""
}

func supportsAWG2Profile(protocolVersion string) bool {
	return protocolVersion == clienttunnel.ProtocolAmneziaWG2 ||
		protocolVersion == clienttunnel.ProtocolAmneziaWG3
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
