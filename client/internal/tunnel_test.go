package internal

import (
	"context"
	"errors"
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
		WgPubKey:              peerKey,
		TunnelMode:            mgmProto.TunnelMode_TunnelModeStandard,
		TunnelProtocolVersion: tunnel.ProtocolAmneziaWG2,
		TunnelProfileRevision: 4,
		TunnelTransitionId:    "rollback-1",
		TunnelEffectiveAt:     timestamppb.New(time.Now().Add(time.Minute)),
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
		WgPubKey:              "peer-key",
		TunnelMode:            mgmProto.TunnelMode_TunnelModeStandard,
		TunnelProtocolVersion: tunnel.ProtocolAmneziaWG2,
		TunnelProfileRevision: 4,
		TunnelTransitionId:    "rollback-1",
		TunnelEffectiveAt:     timestamppb.New(time.Now().Add(time.Minute)),
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

func TestPeerTunnelStateAWG3ProfileAcceptsAWG2Peer(t *testing.T) {
	engine := &Engine{config: &EngineConfig{
		TunnelProfile: testAWG3TunnelProfile(),
	}}
	peer := &mgmProto.RemotePeerConfig{
		TunnelMode:            mgmProto.TunnelMode_TunnelModeAmneziaWG,
		TunnelProtocolVersion: tunnel.ProtocolAmneziaWG2,
		TunnelProfileRevision: 4,
		TunnelTransitionId:    "transition-awg2",
		TunnelEffectiveAt:     timestamppb.New(time.Now().Add(-time.Second)),
	}

	state, err := engine.peerTunnelState(peer)
	if err != nil {
		t.Fatalf("resolve AWG2 peer with AWG3 profile: %v", err)
	}
	if state.mode != tunnel.ModeAmneziaWG2 {
		t.Fatalf("unexpected mixed-mode state: %+v", state)
	}
}

func TestPeerTunnelStateAcceptsAWG3Peer(t *testing.T) {
	engine := &Engine{config: &EngineConfig{
		TunnelProfile: testAWG3TunnelProfile(),
	}}
	peer := &mgmProto.RemotePeerConfig{
		TunnelMode:            mgmProto.TunnelMode_TunnelModeAmneziaWG3,
		TunnelProtocolVersion: tunnel.ProtocolAmneziaWG3,
		TunnelProfileRevision: 4,
		TunnelTransitionId:    "transition-awg3",
		TunnelEffectiveAt:     timestamppb.New(time.Now().Add(-time.Second)),
	}

	state, err := engine.peerTunnelState(peer)
	if err != nil {
		t.Fatalf("resolve AWG3 peer: %v", err)
	}
	if state.mode != tunnel.ModeAmneziaWG3 {
		t.Fatalf("unexpected AWG3 state: %+v", state)
	}
}

func TestUpdateTunnelProfileRejectsNonIncreasingRevision(t *testing.T) {
	tests := []struct {
		name     string
		revision uint64
	}{
		{name: "lower", revision: 3},
		{name: "equal", revision: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cancelled := false
			engine := &Engine{
				config: &EngineConfig{TunnelProfile: testTunnelProfile()},
				clientCancel: func() {
					cancelled = true
				},
			}
			profile := testProtoTunnelProfile(test.revision)
			profile.Parameters = []byte(
				`{"h1":"105","h2":"102","h3":"103","h4":"104"}`,
			)

			if err := engine.updateTunnelProfile(profile); err == nil {
				t.Fatal("non-increasing tunnel profile revision was accepted")
			}
			if cancelled {
				t.Fatal("rejected tunnel profile reset the connection")
			}
		})
	}
}

func TestUpdateTunnelProfileResetsForHigherRevision(t *testing.T) {
	cancelled := false
	ctx := CtxInitState(context.Background())
	engine := &Engine{
		ctx:    ctx,
		config: &EngineConfig{TunnelProfile: testTunnelProfile()},
		clientCancel: func() {
			cancelled = true
		},
	}

	err := engine.updateTunnelProfile(testProtoTunnelProfile(5))
	if !errors.Is(err, ErrResetConnection) {
		t.Fatalf("higher revision error = %v, want reset connection", err)
	}
	if !cancelled {
		t.Fatal("higher revision did not reset the connection")
	}
	if _, err := CtxGetState(ctx).Status(); !errors.Is(err, ErrResetConnection) {
		t.Fatalf("context state error = %v, want reset connection", err)
	}
}

func testProtoTunnelProfile(revision uint64) *mgmProto.TunnelProfile {
	return &mgmProto.TunnelProfile{
		ProtocolVersion: tunnel.ProtocolAmneziaWG2,
		Revision:        revision,
		Parameters: []byte(
			`{"h1":"101","h2":"102","h3":"103","h4":"104"}`,
		),
		ServerTime: timestamppb.Now(),
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

func testAWG3TunnelProfile() *tunnel.Profile {
	profile := testTunnelProfile()
	profile.ProtocolVersion = tunnel.ProtocolAmneziaWG3
	return profile
}
