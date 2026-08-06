package tunnel

import (
	"testing"

	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestResolvePairPreferAWG(t *testing.T) {
	ready := readyPeer()

	decision := ResolvePair(
		AccountPolicyPreferAWG,
		ready,
		ready,
		PairState{Mode: proto.TunnelMode_TunnelModeStandard},
	)

	if decision.Blocked || decision.Pending ||
		decision.Mode != proto.TunnelMode_TunnelModeAmneziaWG {
		t.Fatalf("unexpected prefer-AWG decision: %+v", decision)
	}
}

func TestResolvePairLegacyFallback(t *testing.T) {
	ready := readyPeer()
	legacy := PeerState{}

	decision := ResolvePair(
		AccountPolicyPreferAWG,
		ready,
		legacy,
		PairState{Mode: proto.TunnelMode_TunnelModeAmneziaWG},
	)

	if decision.Blocked || decision.Pending ||
		decision.Mode != proto.TunnelMode_TunnelModeStandard {
		t.Fatalf("unexpected legacy decision: %+v", decision)
	}
}

func TestResolvePairDoesNotDowngradeUnreadyHybridPeer(t *testing.T) {
	ready := readyPeer()
	unready := ready
	unready.Ready = false

	decision := ResolvePair(
		AccountPolicyPreferAWG,
		ready,
		unready,
		PairState{Mode: proto.TunnelMode_TunnelModeAmneziaWG},
	)

	if !decision.Pending || decision.Blocked ||
		decision.Mode != proto.TunnelMode_TunnelModeAmneziaWG {
		t.Fatalf("unexpected pending decision: %+v", decision)
	}
}

func TestResolvePairDoesNotBlockMissingReconnectReport(t *testing.T) {
	ready := readyPeer()
	reconnecting := PeerState{
		SupportsHybridAWG2: true,
	}

	decision := ResolvePair(
		AccountPolicyPreferAWG,
		ready,
		reconnecting,
		PairState{Mode: proto.TunnelMode_TunnelModeAmneziaWG},
	)

	if !decision.Pending || decision.Blocked ||
		decision.Mode != proto.TunnelMode_TunnelModeAmneziaWG {
		t.Fatalf("reconnecting peer was not kept pending: %+v", decision)
	}
}

func TestResolvePairBlocksRevisionMismatch(t *testing.T) {
	left := readyPeer()
	right := readyPeer()
	right.ProfileRevision++

	decision := ResolvePair(
		AccountPolicyPreferAWG,
		left,
		right,
		PairState{Mode: proto.TunnelMode_TunnelModeAmneziaWG},
	)

	if !decision.Blocked || decision.Pending {
		t.Fatalf("revision mismatch was not blocked: %+v", decision)
	}
}

func TestResolvePairRequireAWGBlocksLegacy(t *testing.T) {
	decision := ResolvePair(
		AccountPolicyRequireAWG,
		readyPeer(),
		PeerState{},
		PairState{},
	)

	if !decision.Blocked {
		t.Fatalf("required AWG accepted a legacy peer: %+v", decision)
	}
}

func TestResolvePairUserPreferOverridesAccountStandard(t *testing.T) {
	left := readyPeer()
	left.UserPolicy = UserPolicyPreferAWG

	decision := ResolvePair(
		AccountPolicyStandard,
		left,
		readyPeer(),
		PairState{Mode: proto.TunnelMode_TunnelModeStandard},
	)

	if decision.Blocked || decision.Pending ||
		decision.Mode != proto.TunnelMode_TunnelModeAmneziaWG {
		t.Fatalf("user prefer-AWG override was not applied: %+v", decision)
	}
}

func TestResolvePairStandardOnlyVetoesUserPrefer(t *testing.T) {
	left := readyPeer()
	left.UserPolicy = UserPolicyPreferAWG
	right := readyPeer()
	right.UserPolicy = UserPolicyStandardOnly

	decision := ResolvePair(
		AccountPolicyStandard,
		left,
		right,
		PairState{Mode: proto.TunnelMode_TunnelModeStandard},
	)

	if decision.Blocked || decision.Pending ||
		decision.Mode != proto.TunnelMode_TunnelModeStandard {
		t.Fatalf("standard-only veto was not applied: %+v", decision)
	}
}

func readyPeer() PeerState {
	return PeerState{
		SupportsHybridAWG2: true,
		Ready:              true,
		ProtocolVersion:    "awg2",
		ProfileRevision:    7,
	}
}
