package internal

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/iface/tunnel"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestPeerTunnelStateDefaultsToStandard(t *testing.T) {
	engine := &Engine{config: &EngineConfig{}}

	state, err := engine.peerTunnelState(&mgmProto.RemotePeerConfig{})
	if err != nil {
		t.Fatalf("resolve legacy peer: %v", err)
	}
	if state.mode != tunnel.ModeStandard {
		t.Fatalf("expected standard mode, got %s", state.mode)
	}
}

func TestPeerTunnelStateAcceptsMatchingAWG(t *testing.T) {
	engine := &Engine{config: &EngineConfig{
		TunnelProfile: testTunnelProfile(),
	}}
	peer := &mgmProto.RemotePeerConfig{
		TunnelMode:            mgmProto.TunnelMode_TunnelModeAmneziaWG,
		TunnelProtocolVersion: tunnel.ProtocolAmneziaWG2,
		TunnelProfileRevision: 4,
		TunnelTransitionId:    "transition-1",
		TunnelEffectiveAt:     timestamppb.New(time.Now().Add(-time.Second)),
	}

	state, err := engine.peerTunnelState(peer)
	if err != nil {
		t.Fatalf("resolve AWG peer: %v", err)
	}
	if state.mode != tunnel.ModeAmneziaWG || state.profileRevision != 4 {
		t.Fatalf("unexpected AWG state: %+v", state)
	}
}

func TestPeerTunnelStateRejectsProfileMismatch(t *testing.T) {
	engine := &Engine{config: &EngineConfig{
		TunnelProfile: testTunnelProfile(),
	}}
	peer := &mgmProto.RemotePeerConfig{
		TunnelMode:            mgmProto.TunnelMode_TunnelModeAmneziaWG,
		TunnelProtocolVersion: tunnel.ProtocolAmneziaWG2,
		TunnelProfileRevision: 3,
		TunnelTransitionId:    "transition-1",
		TunnelEffectiveAt:     timestamppb.New(time.Now().Add(-time.Second)),
	}

	if _, err := engine.peerTunnelState(peer); err == nil {
		t.Fatal("AWG peer with mismatched profile revision was accepted")
	}
}

func TestPeerTunnelStateKeepsStandardBeforeFutureTransition(t *testing.T) {
	engine := &Engine{config: &EngineConfig{
		TunnelProfile: testTunnelProfile(),
	}}
	peer := &mgmProto.RemotePeerConfig{
		TunnelMode:            mgmProto.TunnelMode_TunnelModeAmneziaWG,
		TunnelProtocolVersion: tunnel.ProtocolAmneziaWG2,
		TunnelProfileRevision: 4,
		TunnelTransitionId:    "transition-1",
		TunnelEffectiveAt:     timestamppb.New(time.Now().Add(time.Minute)),
	}

	state, err := engine.peerTunnelState(peer)
	if err != nil {
		t.Fatalf("resolve future AWG transition: %v", err)
	}
	if state.mode != tunnel.ModeStandard {
		t.Fatalf("future AWG transition applied early: %+v", state)
	}

	target, future, err := engine.targetPeerTunnelState(peer, time.Now())
	if err != nil {
		t.Fatalf("validate future AWG transition: %v", err)
	}
	if !future || target.mode != tunnel.ModeAmneziaWG {
		t.Fatalf("unexpected future AWG target: future=%t state=%+v", future, target)
	}
}

func TestPeerTunnelStateKeepsAWGBeforeScheduledRollback(t *testing.T) {
	peerKey := "peer-key"
	current := peerTunnelState{
		mode:            tunnel.ModeAmneziaWG,
		protocolVersion: tunnel.ProtocolAmneziaWG2,
		profileRevision: 4,
	}
	engine := &Engine{
		config:           &EngineConfig{TunnelProfile: testTunnelProfile()},
		peerTunnelStates: map[string]peerTunnelState{peerKey: current},
	}
	peer := &mgmProto.RemotePeerConfig{
		WgPubKey:           peerKey,
		TunnelMode:         mgmProto.TunnelMode_TunnelModeStandard,
		TunnelTransitionId: "rollback-1",
		TunnelEffectiveAt:  timestamppb.New(time.Now().Add(time.Minute)),
	}

	state, err := engine.peerTunnelState(peer)
	if err != nil {
		t.Fatalf("resolve future standard transition: %v", err)
	}
	if state != current {
		t.Fatalf("scheduled rollback changed mode early: %+v", state)
	}
}

func TestPeerTunnelStateRestoresAWGBeforeRollbackAfterRestart(t *testing.T) {
	engine := &Engine{
		config:           &EngineConfig{TunnelProfile: testTunnelProfile()},
		peerTunnelStates: make(map[string]peerTunnelState),
	}
	peer := &mgmProto.RemotePeerConfig{
		WgPubKey:           "peer-key",
		TunnelMode:         mgmProto.TunnelMode_TunnelModeStandard,
		TunnelTransitionId: "rollback-1",
		TunnelEffectiveAt:  timestamppb.New(time.Now().Add(time.Minute)),
	}

	state, err := engine.peerTunnelState(peer)
	if err != nil {
		t.Fatalf("restore future standard transition: %v", err)
	}
	if state.mode != tunnel.ModeAmneziaWG ||
		state.profileRevision != engine.config.TunnelProfile.Revision {
		t.Fatalf("restart applied scheduled rollback early: %+v", state)
	}
}

func testTunnelProfile() *tunnel.Profile {
	return &tunnel.Profile{
		ProtocolVersion: tunnel.ProtocolAmneziaWG2,
		Revision:        4,
		AWG2: tunnel.AWG2Parameters{
			InitiationHeader: "101",
			ResponseHeader:   "102",
			CookieHeader:     "103",
			TransportHeader:  "104",
		},
	}
}
