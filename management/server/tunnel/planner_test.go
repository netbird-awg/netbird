package tunnel

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	clienttunnel "github.com/netbirdio/netbird/client/iface/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

func TestPlanPeerConfigsIsSymmetric(t *testing.T) {
	now := time.Now().UTC()
	settings := plannerSettings(now.Add(-time.Minute))
	left := plannerPeer("left", now.Add(-time.Minute))
	right := plannerPeer("right", now.Add(-time.Minute))

	leftConfig := PlanPeerConfigs(
		left,
		[]*sharedtypes.ComponentPeer{right},
		settings,
		nil,
		now,
	)[right.ID]
	rightConfig := PlanPeerConfigs(
		right,
		[]*sharedtypes.ComponentPeer{left},
		settings,
		nil,
		now,
	)[left.ID]

	if leftConfig.Mode != rightConfig.Mode ||
		leftConfig.ProtocolVersion != rightConfig.ProtocolVersion ||
		leftConfig.ProfileRevision != rightConfig.ProfileRevision ||
		leftConfig.TransitionID != rightConfig.TransitionID ||
		!leftConfig.EffectiveAt.AsTime().Equal(rightConfig.EffectiveAt.AsTime()) {
		t.Fatalf("asymmetric pair config: left=%+v right=%+v", leftConfig, rightConfig)
	}
	if leftConfig.Mode != proto.TunnelMode_TunnelModeAmneziaWG {
		t.Fatalf("ready Hybrid pair mode = %s", leftConfig.Mode)
	}
}

func TestPlanPeerConfigsFallsBackOnlyForLegacyPeer(t *testing.T) {
	now := time.Now().UTC()
	settings := plannerSettings(now.Add(-time.Minute))
	left := plannerPeer("left", now.Add(-time.Minute))
	legacy := &sharedtypes.ComponentPeer{ID: "legacy"}

	config := PlanPeerConfigs(
		left,
		[]*sharedtypes.ComponentPeer{legacy},
		settings,
		nil,
		now,
	)[legacy.ID]

	if config.Mode != proto.TunnelMode_TunnelModeStandard ||
		config.TransitionID != "" ||
		config.EffectiveAt != nil {
		t.Fatalf("unexpected legacy fallback config: %+v", config)
	}
}

func TestPlanPeerConfigsBlocksRevisionMismatch(t *testing.T) {
	now := time.Now().UTC()
	settings := plannerSettings(now.Add(-time.Minute))
	left := plannerPeer("left", now.Add(-time.Minute))
	right := plannerPeer("right", now.Add(-time.Minute))
	right.TunnelRuntime.ProfileRevision++

	config := PlanPeerConfigs(
		left,
		[]*sharedtypes.ComponentPeer{right},
		settings,
		nil,
		now,
	)[right.ID]

	if config.Mode != proto.TunnelMode_TunnelModeBlocked {
		t.Fatalf("revision mismatch mode = %s", config.Mode)
	}
}

func TestPlanPeerConfigsKeepsStandardDuringProfileRotation(t *testing.T) {
	now := time.Now().UTC()
	settings := plannerSettings(now)
	settings.TunnelProfile.Revision = 8
	left := plannerPeer("left", now.Add(-time.Minute))
	right := plannerPeer("right", now.Add(-time.Minute))

	config := PlanPeerConfigs(
		left,
		[]*sharedtypes.ComponentPeer{right},
		settings,
		nil,
		now,
	)[right.ID]

	if config.Mode != proto.TunnelMode_TunnelModeStandard ||
		config.TransitionID != "" ||
		config.EffectiveAt != nil {
		t.Fatalf("profile rotation did not stay standard: %+v", config)
	}
}

func TestProfileForPeerUsesResponseTime(t *testing.T) {
	now := time.Now().UTC()
	settings := plannerSettings(now.Add(-time.Minute))
	peer := plannerPeer("peer", now.Add(-time.Minute))

	profile := ProfileForPeer(peer, settings, now)
	if profile == nil {
		t.Fatal("Hybrid peer did not receive a profile")
	}
	if !profile.GetServerTime().AsTime().Equal(now) {
		t.Fatalf("server time = %s, want %s", profile.GetServerTime().AsTime(), now)
	}
}

func TestPendingProfileIsDistributedWithoutActivation(t *testing.T) {
	now := time.Now().UTC()
	settings := plannerSettings(now.Add(-time.Minute))
	pendingSettings := plannerAWG3Settings(now)
	settings.TunnelProfilePending = pendingSettings.TunnelProfile
	peer := plannerAWG3Peer("peer", now)

	profile := ProfileForPeer(peer, settings, now)
	if profile == nil || profile.GetProtocolVersion() !=
		clienttunnel.ProtocolAmneziaWG3 {
		t.Fatalf("pending profile was not distributed: %+v", profile)
	}

	config := PlanPeerConfigs(
		peer,
		[]*sharedtypes.ComponentPeer{
			plannerAWG3Peer("remote", now),
		},
		settings,
		nil,
		now,
	)["remote"]
	if config.Mode != proto.TunnelMode_TunnelModeStandard {
		t.Fatalf("pending profile activated before approval: %+v", config)
	}
}

func TestPendingProfileBlocksRequireAWGUntilActivation(t *testing.T) {
	now := time.Now().UTC()
	settings := plannerSettings(now.Add(-time.Minute))
	settings.TunnelPolicy = types.TunnelAccountPolicyRequireAWG
	settings.TunnelProfilePending = plannerAWG3Settings(now).TunnelProfile
	peer := plannerAWG3Peer("peer", now)

	config := PlanPeerConfigs(
		peer,
		[]*sharedtypes.ComponentPeer{
			plannerAWG3Peer("remote", now),
		},
		settings,
		nil,
		now,
	)["remote"]
	if config.Mode != proto.TunnelMode_TunnelModeBlocked {
		t.Fatalf("required AWG used a pending profile: %+v", config)
	}
}

func TestPlanPeerConfigsUsesAWG3ForTwoAWG3Peers(t *testing.T) {
	now := time.Now().UTC()
	settings := plannerAWG3Settings(now.Add(-time.Minute))
	left := plannerAWG3Peer("left", now.Add(-time.Minute))
	right := plannerAWG3Peer("right", now.Add(-time.Minute))

	config := PlanPeerConfigs(
		left,
		[]*sharedtypes.ComponentPeer{right},
		settings,
		nil,
		now,
	)[right.ID]

	if config.Mode != proto.TunnelMode_TunnelModeAmneziaWG3 ||
		config.ProtocolVersion != clienttunnel.ProtocolAmneziaWG3 {
		t.Fatalf("unexpected AWG3 config: %+v", config)
	}
}

func TestPlanPeerConfigsUsesAWG2ForMixedPeers(t *testing.T) {
	now := time.Now().UTC()
	settings := plannerAWG3Settings(now.Add(-time.Minute))
	left := plannerAWG3Peer("left", now.Add(-time.Minute))
	right := plannerPeer("right", now.Add(-time.Minute))

	config := PlanPeerConfigs(
		left,
		[]*sharedtypes.ComponentPeer{right},
		settings,
		nil,
		now,
	)[right.ID]

	if config.Mode != proto.TunnelMode_TunnelModeAmneziaWG ||
		config.ProtocolVersion != clienttunnel.ProtocolAmneziaWG2 {
		t.Fatalf("unexpected mixed-version config: %+v", config)
	}
}

func TestProfileForPeerKeepsAWG3SecretOutOfAWG2Profile(t *testing.T) {
	now := time.Now().UTC()
	settings := plannerAWG3Settings(now.Add(-time.Minute))

	awg3Profile := ProfileForPeer(
		plannerAWG3Peer("awg3", now),
		settings,
		now,
	)
	if awg3Profile == nil {
		t.Fatal("AWG3 peer did not receive a profile")
	}
	if !bytes.Equal(
		awg3Profile.GetHeaderProtectionKey(),
		settings.TunnelProfile.HeaderProtectionKey,
	) {
		t.Fatal("AWG3 peer did not receive the header protection key")
	}

	awg2Profile := ProfileForPeer(plannerPeer("awg2", now), settings, now)
	if awg2Profile == nil {
		t.Fatal("AWG2 peer did not receive a downgraded profile")
	}
	if awg2Profile.GetProtocolVersion() != clienttunnel.ProtocolAmneziaWG2 {
		t.Fatalf("downgraded protocol = %q", awg2Profile.GetProtocolVersion())
	}
	if len(awg2Profile.GetHeaderProtectionKey()) != 0 {
		t.Fatal("AWG2 peer received an AWG3 header protection key")
	}
	var parameters map[string]interface{}
	if err := json.Unmarshal(awg2Profile.GetParameters(), &parameters); err != nil {
		t.Fatalf("decode downgraded parameters: %v", err)
	}
	if _, ok := parameters["content_padding_addition"]; ok {
		t.Fatal("AWG2 peer received AWG3-only parameters")
	}
}

func TestPlanPeerConfigsRequireAWGDoesNotPermitStandardTransition(t *testing.T) {
	now := time.Now().UTC()
	settings := plannerSettings(now.Add(-time.Minute))
	settings.TunnelPolicy = types.TunnelAccountPolicyRequireAWG
	left := plannerPeer("left", now)
	right := plannerPeer("right", now)

	config := PlanPeerConfigs(
		left,
		[]*sharedtypes.ComponentPeer{right},
		settings,
		nil,
		now,
	)[right.ID]

	if config.Mode != proto.TunnelMode_TunnelModeAmneziaWG ||
		config.EffectiveAt.AsTime().After(now) {
		t.Fatalf("required AWG allowed a standard transition window: %+v", config)
	}
}

func TestPlanPeerConfigsDoesNotScheduleNoopStandardTransition(t *testing.T) {
	now := time.Now().UTC()
	settings := plannerSettings(now.Add(-time.Minute))
	settings.TunnelPolicy = types.TunnelAccountPolicyStandard
	settings.TunnelPolicyUpdatedAt = now
	left := &sharedtypes.ComponentPeer{
		ID:                 "left",
		SupportsHybridAWG2: true,
	}
	right := &sharedtypes.ComponentPeer{
		ID:                 "right",
		SupportsHybridAWG2: true,
	}

	config := PlanPeerConfigs(
		left,
		[]*sharedtypes.ComponentPeer{right},
		settings,
		nil,
		now,
	)[right.ID]

	if config.Mode != proto.TunnelMode_TunnelModeStandard ||
		config.TransitionID != "" ||
		config.EffectiveAt != nil {
		t.Fatalf("standard pair received a no-op transition: %+v", config)
	}
}

func TestPlanPeerConfigsSchedulesAWGRollback(t *testing.T) {
	now := time.Now().UTC()
	settings := plannerSettings(now.Add(-time.Minute))
	settings.TunnelPolicy = types.TunnelAccountPolicyStandard
	settings.TunnelPolicyUpdatedAt = now
	left := plannerPeer("left", now.Add(-time.Minute))
	right := plannerPeer("right", now.Add(-time.Minute))

	config := PlanPeerConfigs(
		left,
		[]*sharedtypes.ComponentPeer{right},
		settings,
		nil,
		now,
	)[right.ID]

	if config.Mode != proto.TunnelMode_TunnelModeStandard ||
		config.TransitionID == "" ||
		config.EffectiveAt == nil ||
		!config.EffectiveAt.AsTime().After(now) {
		t.Fatalf("AWG rollback was not scheduled: %+v", config)
	}
}

func plannerSettings(updatedAt time.Time) *types.Settings {
	return &types.Settings{
		TunnelPolicy:          types.TunnelAccountPolicyPreferAWG,
		TunnelPolicyUpdatedAt: updatedAt,
		TunnelProfile: &types.TunnelProfile{
			ProtocolVersion: "awg2",
			Revision:        7,
			Parameters:      json.RawMessage(`{"h1":"101"}`),
			UpdatedAt:       updatedAt,
		},
	}
}

func plannerPeer(id string, readyAt time.Time) *sharedtypes.ComponentPeer {
	return &sharedtypes.ComponentPeer{
		ID:                 id,
		SupportsHybridAWG2: true,
		TunnelRuntime: sharedtypes.TunnelRuntimeInfo{
			ProtocolVersion:   "awg2",
			ProfileRevision:   7,
			AdapterRevision:   HybridAWG2AdapterRevision,
			Ready:             true,
			UpdatedAt:         readyAt,
			LastReadyProtocol: "awg2",
			LastReadyRevision: 7,
			LastReadyAt:       readyAt,
		},
	}
}

func plannerAWG3Settings(updatedAt time.Time) *types.Settings {
	return &types.Settings{
		TunnelPolicy:          types.TunnelAccountPolicyPreferAWG,
		TunnelPolicyUpdatedAt: updatedAt,
		TunnelProfile: &types.TunnelProfile{
			ProtocolVersion: clienttunnel.ProtocolAmneziaWG3,
			Revision:        7,
			Parameters: json.RawMessage(
				`{"s1":12,"s2":12,"s3":12,"s4":12,` +
					`"h1":"101","h2":"102","h3":"103","h4":"104",` +
					`"content_padding_addition":"1-16"}`,
			),
			UpdatedAt:           updatedAt,
			HeaderProtectionKey: bytes.Repeat([]byte{0x5a}, 32),
		},
	}
}

func plannerAWG3Peer(id string, readyAt time.Time) *sharedtypes.ComponentPeer {
	return &sharedtypes.ComponentPeer{
		ID:                 id,
		SupportsHybridAWG2: true,
		SupportsHybridAWG3: true,
		TunnelRuntime: sharedtypes.TunnelRuntimeInfo{
			ProtocolVersion:   clienttunnel.ProtocolAmneziaWG3,
			ProfileRevision:   7,
			AdapterRevision:   HybridAWG3AdapterRevision,
			Ready:             true,
			UpdatedAt:         readyAt,
			LastReadyProtocol: clienttunnel.ProtocolAmneziaWG3,
			LastReadyRevision: 7,
			LastReadyAt:       readyAt,
		},
	}
}
