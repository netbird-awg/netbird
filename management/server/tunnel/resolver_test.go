package tunnel

import (
	"testing"

	clienttunnel "github.com/netbirdio/netbird/client/iface/tunnel"
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
		AssignedProtocol:   clienttunnel.ProtocolAmneziaWG2,
		AssignedRevision:   7,
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

func TestResolvePairWaitsForProfileRotation(t *testing.T) {
	left := readyPeer()
	right := readyPeer()
	left.ProfileRevision = 6
	right.ProfileRevision = 6

	decision := ResolvePair(
		AccountPolicyPreferAWG,
		left,
		right,
		PairState{Mode: proto.TunnelMode_TunnelModeStandard},
	)

	if decision.Blocked || !decision.Pending ||
		decision.Mode != proto.TunnelMode_TunnelModeStandard {
		t.Fatalf("profile rotation did not stay pending: %+v", decision)
	}
}

func TestResolvePairPrefersAWG3ForTwoAWG3Peers(t *testing.T) {
	left := readyAWG3Peer()
	right := readyAWG3Peer()

	decision := ResolvePair(
		AccountPolicyPreferAWG,
		left,
		right,
		PairState{Mode: proto.TunnelMode_TunnelModeStandard},
	)

	if decision.Blocked || decision.Pending ||
		decision.Mode != proto.TunnelMode_TunnelModeAmneziaWG3 {
		t.Fatalf("unexpected AWG3 decision: %+v", decision)
	}
}

func TestResolvePairUsesAWG2ForMixedPeers(t *testing.T) {
	left := readyAWG3Peer()
	right := readyPeer()

	decision := ResolvePair(
		AccountPolicyPreferAWG,
		left,
		right,
		PairState{Mode: proto.TunnelMode_TunnelModeStandard},
	)

	if decision.Blocked || decision.Pending ||
		decision.Mode != proto.TunnelMode_TunnelModeAmneziaWG {
		t.Fatalf("unexpected mixed-version decision: %+v", decision)
	}
}

func TestResolvePairKeepsAWG3PendingDuringReconnect(t *testing.T) {
	left := readyAWG3Peer()
	right := readyAWG3Peer()
	right.Ready = false
	right.ProtocolVersion = ""

	decision := ResolvePair(
		AccountPolicyPreferAWG,
		left,
		right,
		PairState{Mode: proto.TunnelMode_TunnelModeAmneziaWG3},
	)

	if decision.Blocked || !decision.Pending ||
		decision.Mode != proto.TunnelMode_TunnelModeAmneziaWG3 {
		t.Fatalf("AWG3 reconnect caused a downgrade: %+v", decision)
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
		AssignedProtocol:   clienttunnel.ProtocolAmneziaWG2,
		AssignedRevision:   7,
		ProtocolVersion:    clienttunnel.ProtocolAmneziaWG2,
		ProfileRevision:    7,
		AdapterCompatible:  true,
	}
}

func readyAWG3Peer() PeerState {
	return PeerState{
		SupportsHybridAWG2: true,
		SupportsHybridAWG3: true,
		Ready:              true,
		AssignedProtocol:   clienttunnel.ProtocolAmneziaWG3,
		AssignedRevision:   7,
		ProtocolVersion:    clienttunnel.ProtocolAmneziaWG3,
		ProfileRevision:    7,
		AdapterCompatible:  true,
	}
}
