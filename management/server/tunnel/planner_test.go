package tunnel

import (
	"encoding/json"
	"testing"
	"time"

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
