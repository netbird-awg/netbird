package internal

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/iface/tunnel"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

func TestTunnelProfileClockSkewBoundaries(t *testing.T) {
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		skew    time.Duration
		wantMS  int64
		warning bool
		hard    bool
	}{
		{name: "zero"},
		{name: "client ahead exact warning", skew: 2 * time.Second, wantMS: 2000},
		{name: "client behind exact warning", skew: -2 * time.Second, wantMS: -2000},
		{name: "client ahead warning", skew: 2*time.Second + time.Millisecond, wantMS: 2001, warning: true},
		{name: "client behind warning", skew: -2*time.Second - time.Millisecond, wantMS: -2001, warning: true},
		{name: "client ahead exact hard", skew: 5 * time.Minute, wantMS: 300000, warning: true},
		{name: "client behind exact hard", skew: -5 * time.Minute, wantMS: -300000, warning: true},
		{name: "client ahead over hard", skew: 5*time.Minute + time.Millisecond, wantMS: 300001, warning: true, hard: true},
		{name: "client behind over hard", skew: -5*time.Minute - time.Millisecond, wantMS: -300001, warning: true, hard: true},
		{name: "network delay", skew: 3 * time.Second, wantMS: 3000, warning: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := testProtoTunnelProfile(4)
			profile.ServerTime = timestamppb.New(now.Add(-test.skew))
			result, err := tunnelProfileFromProtoAt(profile, now)
			if test.hard {
				if err == nil || result.Profile != nil || result.identity == nil {
					t.Fatalf("hard skew accepted: result=%+v err=%v", result, err)
				}
				if result.Runtime.ErrorCode != sharedtypes.TunnelRuntimeErrorClockSkew {
					t.Fatalf("hard skew code = %q", result.Runtime.ErrorCode)
				}
			} else if err != nil || result.Profile == nil || !result.Runtime.Ready {
				t.Fatalf("bounded skew rejected: result=%+v err=%v", result, err)
			}
			if result.SkewMS != test.wantMS || result.Warning != test.warning {
				t.Fatalf("skew result = %+v, want ms=%d warning=%t", result, test.wantMS, test.warning)
			}
		})
	}
}

func TestTunnelProfileClockSkewRejectsExtremeTimestamps(t *testing.T) {
	oldest := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	newest := time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name       string
		serverTime time.Time
		now        time.Time
	}{
		{name: "client far ahead", serverTime: oldest, now: newest},
		{name: "client far behind", serverTime: newest, now: oldest},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := testProtoTunnelProfile(4)
			profile.ServerTime = timestamppb.New(test.serverTime)
			result, err := tunnelProfileFromProtoAt(profile, test.now)
			if err == nil ||
				result.Runtime.ErrorCode != sharedtypes.TunnelRuntimeErrorClockSkew {
				t.Fatalf("extreme skew result=%+v err=%v", result, err)
			}
		})
	}
}

func TestUpdateTunnelProfileRefreshesSameRevisionSkewAndTransition(t *testing.T) {
	now := time.Date(2040, time.August, 8, 12, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	engine := &Engine{
		ctx:                      ctx,
		now:                      func() time.Time { return now },
		config:                   &EngineConfig{TunnelProfile: testTunnelProfile()},
		peerTunnelStates:         make(map[string]peerTunnelState),
		pendingTunnelTransitions: make(map[string]pendingTunnelTransition),
	}
	engine.config.TunnelRuntime = tunnelRuntimeForProfile(engine.config.TunnelProfile)
	peer := &mgmProto.RemotePeerConfig{
		WgPubKey:              "peer",
		TunnelMode:            mgmProto.TunnelMode_TunnelModeAmneziaWG,
		TunnelProtocolVersion: tunnel.ProtocolAmneziaWG2,
		TunnelProfileRevision: 4,
		TunnelTransitionId:    "transition",
		TunnelEffectiveAt:     timestamppb.New(now.Add(time.Hour)),
	}
	requireSyncTransitions(t, engine, peer)
	first := engine.pendingTunnelTransitions[peer.WgPubKey].effectiveAt

	profile := testProtoTunnelProfile(4)
	profile.ServerTime = timestamppb.New(now.Add(-3 * time.Second))
	if err := engine.updateTunnelProfileAt(profile, now); err != nil {
		t.Fatalf("refresh same revision: %v", err)
	}
	requireSyncTransitions(t, engine, peer)
	second := engine.pendingTunnelTransitions[peer.WgPubKey].effectiveAt
	if engine.config.TunnelProfile.EstimatedClockSkewMS != 3000 ||
		second != first+int64(3*time.Second) {
		t.Fatalf("skew/timer not refreshed: skew=%d first=%d second=%d", engine.config.TunnelProfile.EstimatedClockSkewMS, first, second)
	}

	cancel()
	engine.shutdownWg.Wait()
}

func TestEffectiveAtUsesSignedClockSkew(t *testing.T) {
	serverEffectiveAt := time.Date(2026, time.August, 8, 13, 0, 0, 0, time.UTC)
	for _, skewMS := range []int64{-3000, 3000} {
		engine := &Engine{config: &EngineConfig{
			TunnelProfile: testTunnelProfile(),
			TunnelRuntime: &system.TunnelRuntimeInfo{Ready: true, EstimatedClockSkewMS: skewMS},
		}}
		peer := &mgmProto.RemotePeerConfig{
			TunnelMode:            mgmProto.TunnelMode_TunnelModeAmneziaWG,
			TunnelProtocolVersion: tunnel.ProtocolAmneziaWG2,
			TunnelProfileRevision: 4,
			TunnelTransitionId:    "transition",
			TunnelEffectiveAt:     timestamppb.New(serverEffectiveAt),
		}
		state, _, err := engine.targetPeerTunnelState(peer, serverEffectiveAt.Add(-time.Hour))
		if err != nil {
			t.Fatalf("resolve skew %d: %v", skewMS, err)
		}
		want := serverEffectiveAt.Add(time.Duration(skewMS) * time.Millisecond).UnixNano()
		if state.effectiveAt != want {
			t.Fatalf("effective_at for skew %d = %d, want %d", skewMS, state.effectiveAt, want)
		}
	}
}

func TestHardTunnelProfileFailureReportsAndRecovers(t *testing.T) {
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	var reports []*system.Info
	engine := &Engine{
		ctx:    CtxInitState(context.Background()),
		config: &EngineConfig{TunnelProfile: testTunnelProfile()},
		mgmClient: &mgm.MockClient{SyncMetaFunc: func(info *system.Info) error {
			reports = append(reports, info)
			return nil
		}},
		clientCancel: func() {},
	}
	engine.config.TunnelRuntime = tunnelRuntimeForProfile(engine.config.TunnelProfile)

	hard := testProtoTunnelProfile(5)
	hard.ServerTime = timestamppb.New(now.Add(-5*time.Minute - time.Millisecond))
	if err := engine.updateTunnelProfileAt(hard, now); err != nil {
		t.Fatalf("hard skew interrupted control plane: %v", err)
	}
	if len(reports) != 1 || reports[0].GoOS == "" ||
		reports[0].TunnelRuntime == nil {
		t.Fatalf("hard skew did not use full SyncMeta: %+v", reports)
	}
	runtime := reports[0].TunnelRuntime
	if runtime.Ready ||
		runtime.ErrorCode != sharedtypes.TunnelRuntimeErrorClockSkew ||
		runtime.ProtocolVersion != tunnel.ProtocolAmneziaWG2 ||
		runtime.ProfileRevision != 5 || runtime.EstimatedClockSkewMS != 300001 {
		t.Fatalf("hard skew report = %+v", reports[0])
	}
	if engine.config.TunnelProfile.Revision != 4 || engine.tunnelRuntimeReady() {
		t.Fatalf("hard skew changed loaded profile/runtime: %+v", engine.config)
	}

	valid := testProtoTunnelProfile(5)
	valid.ServerTime = timestamppb.New(now)
	err := engine.updateTunnelProfileAt(valid, now)
	if !errors.Is(err, ErrResetConnection) || engine.config.TunnelRuntime.Ready {
		t.Fatalf("higher revision did not recover: runtime=%+v err=%v", engine.config.TunnelRuntime, err)
	}
	if len(reports) != 1 {
		t.Fatalf("higher revision reported Ready before load: %+v", reports)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	loaded, err := createEngineConfigAt(
		key,
		&profilemanager.Config{DisableIPv6: true},
		&mgmProto.PeerConfig{
			Address:       "100.64.0.1/32",
			TunnelProfile: valid,
		},
		"",
		now,
	)
	if err != nil {
		t.Fatalf("load corrected profile in new engine config: %v", err)
	}
	info := &system.Info{}
	(&Engine{config: loaded}).applyInfoFlags(info)
	if info.TunnelRuntime == nil || !info.TunnelRuntime.Ready ||
		info.TunnelRuntime.ProfileRevision != 5 || info.TunnelRuntime.ErrorCode != "" {
		t.Fatalf("new engine loaded runtime = %+v", info.TunnelRuntime)
	}
}

func TestInvalidTunnelProfileReportsStableCode(t *testing.T) {
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	var reported *system.TunnelRuntimeInfo
	engine := &Engine{
		ctx:    context.Background(),
		config: &EngineConfig{TunnelProfile: testTunnelProfile()},
		mgmClient: &mgm.MockClient{SyncMetaFunc: func(info *system.Info) error {
			reported = info.TunnelRuntime
			return nil
		}},
	}
	invalid := testProtoTunnelProfile(5)
	invalid.ServerTime = timestamppb.New(now)
	invalid.Parameters = []byte(`{"h1":"secret-like-invalid"}`)
	if err := engine.updateTunnelProfileAt(invalid, now); err != nil {
		t.Fatalf("invalid profile interrupted control plane: %v", err)
	}
	if reported == nil || reported.Ready ||
		reported.ErrorCode != sharedtypes.TunnelRuntimeErrorProfileInvalid ||
		reported.ProtocolVersion != tunnel.ProtocolAmneziaWG2 ||
		reported.ProfileRevision != 5 || reported.EstimatedClockSkewMS != 0 {
		t.Fatalf("invalid profile report = %+v", reported)
	}
}

func TestNonIncreasingInvalidProfilesPreserveRuntime(t *testing.T) {
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	mutations := []struct {
		name   string
		mutate func(*mgmProto.TunnelProfile)
	}{
		{
			name: "invalid timestamp",
			mutate: func(profile *mgmProto.TunnelProfile) {
				profile.ServerTime = &timestamppb.Timestamp{Seconds: 253402300800}
			},
		},
		{
			name: "hard skew",
			mutate: func(profile *mgmProto.TunnelProfile) {
				profile.ServerTime = timestamppb.New(
					now.Add(-5*time.Minute - time.Millisecond),
				)
			},
		},
		{
			name: "invalid parameters",
			mutate: func(profile *mgmProto.TunnelProfile) {
				profile.Parameters = []byte(`{"h1":"invalid"}`)
			},
		},
		{
			name: "invalid key",
			mutate: func(profile *mgmProto.TunnelProfile) {
				profile.HeaderProtectionKey = []byte("unexpected")
			},
		},
	}
	for _, revision := range []uint64{3, 4} {
		for _, mutation := range mutations {
			if revision == 4 && mutation.name == "hard skew" {
				continue
			}
			t.Run(fmt.Sprintf("revision_%d/%s", revision, mutation.name), func(t *testing.T) {
				profile := testProtoTunnelProfile(revision)
				profile.ServerTime = timestamppb.New(now)
				mutation.mutate(profile)
				originalRuntime := tunnelRuntimeForProfile(testTunnelProfile())
				reports := 0
				engine := &Engine{
					config: &EngineConfig{
						TunnelProfile: testTunnelProfile(),
						TunnelRuntime: originalRuntime,
					},
					mgmClient: &mgm.MockClient{SyncMetaFunc: func(*system.Info) error {
						reports++
						return nil
					}},
				}

				err := engine.updateTunnelProfileAt(profile, now)
				wantErr := "tunnel profile revision " +
					fmt.Sprint(revision) + " does not advance beyond 4"
				if err == nil || err.Error() != wantErr {
					t.Fatalf("error = %v, want %q", err, wantErr)
				}
				if engine.config.TunnelRuntime != originalRuntime ||
					engine.config.TunnelProfile.EstimatedClockSkewMS != 0 ||
					reports != 0 {
					t.Fatalf(
						"rejected profile changed state: runtime=%+v reports=%d",
						engine.config.TunnelRuntime,
						reports,
					)
				}
			})
		}
	}
}

func TestEqualRevisionProtocolChangePreservesRuntime(t *testing.T) {
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	profile := testProtoTunnelProfile(4)
	profile.ProtocolVersion = tunnel.ProtocolAmneziaWG3
	profile.ServerTime = timestamppb.New(now)
	originalRuntime := tunnelRuntimeForProfile(testTunnelProfile())
	engine := &Engine{config: &EngineConfig{
		TunnelProfile: testTunnelProfile(),
		TunnelRuntime: originalRuntime,
	}}

	if err := engine.updateTunnelProfileAt(profile, now); err == nil {
		t.Fatal("equal revision protocol change was accepted")
	}
	if engine.config.TunnelRuntime != originalRuntime {
		t.Fatal("equal revision protocol change poisoned runtime")
	}
}

func TestEqualSameIdentityHardSkewReportsAndRecovers(t *testing.T) {
	now := time.Date(2026, time.August, 8, 12, 0, 0, 0, time.UTC)
	var reports []*system.TunnelRuntimeInfo
	engine := &Engine{
		ctx: context.Background(),
		config: &EngineConfig{
			TunnelProfile: testTunnelProfile(),
			TunnelRuntime: tunnelRuntimeForProfile(testTunnelProfile()),
		},
		mgmClient: &mgm.MockClient{SyncMetaFunc: func(info *system.Info) error {
			if info.TunnelRuntime == nil {
				t.Fatal("runtime report is missing")
			}
			copy := *info.TunnelRuntime
			reports = append(reports, &copy)
			return nil
		}},
	}
	hard := testProtoTunnelProfile(4)
	hard.ServerTime = timestamppb.New(now.Add(-5*time.Minute - time.Millisecond))
	if err := engine.updateTunnelProfileAt(hard, now); err != nil {
		t.Fatalf("equal identity hard skew: %v", err)
	}
	if len(reports) != 1 || reports[0].Ready ||
		reports[0].ErrorCode != sharedtypes.TunnelRuntimeErrorClockSkew ||
		engine.tunnelRuntimeReady() {
		t.Fatalf("hard-skew runtime reports = %+v", reports)
	}
	if err := engine.updateTunnelProfileAt(hard, now); err != nil {
		t.Fatalf("repeat equal identity hard skew: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("identical hard-skew report repeated: %+v", reports)
	}

	profile := testProtoTunnelProfile(4)
	profile.ServerTime = timestamppb.New(now)
	if err := engine.updateTunnelProfileAt(profile, now); err != nil {
		t.Fatalf("same revision recovery: %v", err)
	}
	if err := engine.updateTunnelProfileAt(profile, now); err != nil {
		t.Fatalf("repeat same revision recovery: %v", err)
	}
	if len(reports) != 2 || !reports[1].Ready || reports[1].ErrorCode != "" {
		t.Fatalf("recovery reports = %+v", reports)
	}
}

func requireSyncTransitions(t *testing.T, engine *Engine, peer *mgmProto.RemotePeerConfig) {
	t.Helper()
	if err := engine.syncPeerTunnelTransitions([]*mgmProto.RemotePeerConfig{peer}); err != nil {
		t.Fatalf("sync transitions: %v", err)
	}
}
