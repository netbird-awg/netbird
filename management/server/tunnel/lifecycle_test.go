package tunnel

import (
	"errors"
	"reflect"
	"testing"
	"time"

	clienttunnel "github.com/netbirdio/netbird/client/iface/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

func TestEvaluateReadinessAggregatesWithoutPeerDetails(t *testing.T) {
	now := time.Now().UTC()
	pending := validTunnelProfile(7, now.Add(-time.Minute))
	ready := lifecyclePeer("ready-id", pending, now, true, "")
	waiting := lifecyclePeer(
		"waiting-id",
		pending,
		now,
		false,
		sharedtypes.TunnelRuntimeErrorClockSkew,
	)
	result := EvaluateReadiness(
		pending,
		[]*sharedtypes.ComponentPeer{ready, waiting},
		3,
		4,
		now,
	)

	if result.State != ReadinessWaiting || result.Eligible != 2 ||
		result.Ready != 1 || result.Waiting != 1 ||
		result.Eligible != result.Ready+result.Waiting ||
		result.ExcludedOffline != 3 || result.Incompatible != 4 ||
		result.PendingRevision == nil || *result.PendingRevision != 7 ||
		result.ErrorCounts[sharedtypes.TunnelRuntimeErrorClockSkew] != 1 {
		t.Fatalf("unexpected readiness aggregate: %+v", result)
	}
	if _, ok := result.ErrorCounts[ready.ID]; ok {
		t.Fatal("readiness aggregate exposed a peer identifier")
	}
}

func TestEvaluateReadinessZeroEligibleIsReady(t *testing.T) {
	now := time.Now().UTC()
	result := EvaluateReadiness(
		validTunnelProfile(1, now),
		nil,
		2,
		3,
		now,
	)
	if result.State != ReadinessReady || result.Eligible != 0 ||
		result.Ready != 0 || result.Waiting != 0 {
		t.Fatalf("zero eligible readiness = %+v", result)
	}
}

func TestApplyLifecycleStagesMonotonicAndIsIdempotent(t *testing.T) {
	now := time.Now().UTC()
	current := &types.Settings{
		DNSDomain:     "unchanged.example",
		TunnelProfile: validTunnelProfile(8, now.Add(-time.Hour)),
	}
	request := LifecycleRequest{
		Action:          LifecycleActionStage,
		ProtocolVersion: clienttunnel.ProtocolAmneziaWG3,
	}
	staged, changed, err := ApplyLifecycle(
		current,
		request,
		Readiness{},
		now,
	)
	if err != nil {
		t.Fatalf("stage profile: %v", err)
	}
	if !changed || staged.TunnelProfilePending == nil ||
		staged.TunnelProfilePending.Revision != 9 ||
		staged.DNSDomain != current.DNSDomain {
		t.Fatalf("unexpected staged state: %+v", staged)
	}

	repeated, changed, err := ApplyLifecycle(
		staged,
		request,
		Readiness{},
		now.Add(time.Minute),
	)
	if err != nil || changed ||
		repeated.TunnelProfilePending.Revision != 9 ||
		!repeated.TunnelProfilePending.UpdatedAt.Equal(
			staged.TunnelProfilePending.UpdatedAt,
		) {
		t.Fatalf("repeat stage was not idempotent: %+v, %v", repeated, err)
	}
}

func TestApplyLifecycleRejectsStaleExpectationsWithoutMutation(t *testing.T) {
	now := time.Now().UTC()
	current := &types.Settings{
		TunnelProfile:        validTunnelProfile(4, now),
		TunnelProfilePending: validTunnelProfile(5, now),
	}
	before := current.Copy()
	expected := uint64(3)
	_, _, err := ApplyLifecycle(
		current,
		LifecycleRequest{
			Action:                 LifecycleActionSetPolicy,
			Policy:                 types.TunnelAccountPolicyPreferAWG,
			ExpectedActiveRevision: &expected,
		},
		Readiness{},
		now,
	)
	var lifecycleErr *LifecycleError
	if !errors.As(err, &lifecycleErr) ||
		lifecycleErr.Code != LifecycleErrorStaleActiveRevision {
		t.Fatalf("stale active error = %v", err)
	}
	if !reflect.DeepEqual(before, current) {
		t.Fatal("stale request mutated current settings")
	}
}

func TestApplyLifecycleCancelRequiresPolicyDowngradeWithoutActive(t *testing.T) {
	now := time.Now().UTC()
	pending := validTunnelProfile(4, now)
	current := &types.Settings{
		TunnelPolicy:         types.TunnelAccountPolicyRequireAWG,
		TunnelProfilePending: pending,
	}
	target := pending.Revision
	_, _, err := ApplyLifecycle(
		current,
		LifecycleRequest{
			Action:         LifecycleActionCancelPending,
			TargetRevision: &target,
		},
		Readiness{},
		now,
	)
	if err == nil {
		t.Fatal("cancel without active profile retained require_awg")
	}

	updated, changed, err := ApplyLifecycle(
		current,
		LifecycleRequest{
			Action:         LifecycleActionCancelPending,
			TargetRevision: &target,
			Policy:         types.TunnelAccountPolicyStandard,
		},
		Readiness{},
		now,
	)
	if err != nil || !changed || updated.TunnelProfilePending != nil ||
		updated.TunnelPolicy != types.TunnelAccountPolicyStandard {
		t.Fatalf("safe cancellation failed: %+v, %v", updated, err)
	}
}

func TestApplyLifecycleCancelReplayWithoutExpectedRevision(t *testing.T) {
	now := time.Now().UTC()
	target := uint64(2)
	request := LifecycleRequest{
		Action:         LifecycleActionCancelPending,
		TargetRevision: &target,
	}
	current := &types.Settings{
		TunnelPolicy:         types.TunnelAccountPolicyStandard,
		TunnelProfile:        validTunnelProfile(1, now.Add(-time.Hour)),
		TunnelProfilePending: validTunnelProfile(target, now),
	}

	cancelled, changed, err := ApplyLifecycle(
		current,
		request,
		Readiness{},
		now,
	)
	if err != nil || !changed || cancelled.TunnelProfilePending != nil {
		t.Fatalf("cancel pending profile: %+v, %v", cancelled, err)
	}
	afterCancel := cancelled.Copy()

	replayed, changed, err := ApplyLifecycle(
		cancelled,
		request,
		Readiness{},
		now.Add(time.Minute),
	)
	if err != nil || changed || !reflect.DeepEqual(afterCancel, replayed) {
		t.Fatalf("cancel replay changed state: %+v, %v", replayed, err)
	}
}

func TestApplyLifecycleActivationUsesReadinessAggregate(t *testing.T) {
	now := time.Now().UTC()
	pending := validTunnelProfile(2, now)
	current := &types.Settings{TunnelProfilePending: pending}
	target := pending.Revision
	_, _, err := ApplyLifecycle(
		current,
		LifecycleRequest{
			Action:         LifecycleActionActivate,
			TargetRevision: &target,
		},
		Readiness{State: ReadinessWaiting},
		now,
	)
	var lifecycleErr *LifecycleError
	if !errors.As(err, &lifecycleErr) ||
		lifecycleErr.Code != LifecycleErrorNotReady {
		t.Fatalf("activation readiness error = %v", err)
	}
}

func TestApplyLifecycleOriginalRequestReplayPrecedesExpectations(t *testing.T) {
	now := time.Now().UTC()
	one := uint64(1)
	two := uint64(2)
	zero := uint64(0)
	previous := validTunnelProfile(1, now.Add(-time.Hour))
	rollbackPending := validTunnelProfile(3, now)
	rollbackPending.ProtocolVersion = previous.ProtocolVersion
	rollbackPending.Parameters = previous.Parameters
	tests := []struct {
		name    string
		current *types.Settings
		request LifecycleRequest
	}{
		{
			name: "stage",
			current: &types.Settings{
				TunnelProfile:        validTunnelProfile(1, now),
				TunnelProfilePending: validTunnelProfile(2, now),
			},
			request: LifecycleRequest{
				Action:                  LifecycleActionStage,
				ProtocolVersion:         clienttunnel.ProtocolAmneziaWG2,
				ExpectedActiveRevision:  &one,
				ExpectedPendingRevision: &zero,
			},
		},
		{
			name: "activate",
			current: &types.Settings{
				TunnelProfile: validTunnelProfile(2, now),
			},
			request: LifecycleRequest{
				Action:                  LifecycleActionActivate,
				TargetRevision:          &two,
				ExpectedActiveRevision:  &one,
				ExpectedPendingRevision: &two,
			},
		},
		{
			name: "cancel",
			current: &types.Settings{
				TunnelPolicy:  types.TunnelAccountPolicyStandard,
				TunnelProfile: validTunnelProfile(3, now),
			},
			request: LifecycleRequest{
				Action:                  LifecycleActionCancelPending,
				TargetRevision:          &two,
				Policy:                  types.TunnelAccountPolicyStandard,
				ExpectedActiveRevision:  &one,
				ExpectedPendingRevision: &two,
			},
		},
		{
			name: "rollback",
			current: &types.Settings{
				TunnelProfile:           validTunnelProfile(2, now),
				TunnelProfilePending:    rollbackPending,
				TunnelProfilePrevious:   previous,
				TunnelProfileGraceUntil: now.Add(time.Hour),
			},
			request: LifecycleRequest{
				Action:                  LifecycleActionRollback,
				TargetRevision:          &one,
				ExpectedActiveRevision:  &two,
				ExpectedPendingRevision: &zero,
			},
		},
		{
			name: "set policy",
			current: &types.Settings{
				TunnelPolicy:  types.TunnelAccountPolicyPreferAWG,
				TunnelProfile: validTunnelProfile(2, now),
			},
			request: LifecycleRequest{
				Action:                 LifecycleActionSetPolicy,
				Policy:                 types.TunnelAccountPolicyPreferAWG,
				ExpectedActiveRevision: &one,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := test.current.Copy()
			updated, changed, err := ApplyLifecycle(
				test.current,
				test.request,
				Readiness{State: ReadinessReady},
				now,
			)
			if err != nil || changed || !reflect.DeepEqual(before, updated) {
				t.Fatalf("terminal replay changed state: %+v, %v", updated, err)
			}
		})
	}
}

func TestApplyLifecycleTrueStaleTargetStillConflicts(t *testing.T) {
	now := time.Now().UTC()
	target := uint64(2)
	expected := uint64(3)
	_, _, err := ApplyLifecycle(
		&types.Settings{TunnelProfilePending: validTunnelProfile(3, now)},
		LifecycleRequest{
			Action:                  LifecycleActionActivate,
			TargetRevision:          &target,
			ExpectedPendingRevision: &expected,
		},
		Readiness{State: ReadinessReady},
		now,
	)
	var lifecycleErr *LifecycleError
	if !errors.As(err, &lifecycleErr) ||
		lifecycleErr.Code != LifecycleErrorStaleTargetRevision {
		t.Fatalf("stale target error = %v", err)
	}
}

func TestApplyLifecycleCancelStaleTargetStillConflictsWhilePending(t *testing.T) {
	now := time.Now().UTC()
	target := uint64(2)
	_, _, err := ApplyLifecycle(
		&types.Settings{TunnelProfilePending: validTunnelProfile(3, now)},
		LifecycleRequest{
			Action:         LifecycleActionCancelPending,
			TargetRevision: &target,
		},
		Readiness{},
		now,
	)
	var lifecycleErr *LifecycleError
	if !errors.As(err, &lifecycleErr) ||
		lifecycleErr.Code != LifecycleErrorStaleTargetRevision {
		t.Fatalf("stale cancel target error = %v", err)
	}
}

func TestApplyLifecycleNonTerminalStaleExpectationsConflictForEveryAction(
	t *testing.T,
) {
	now := time.Now().UTC()
	stale := uint64(1)
	active := validTunnelProfile(2, now)
	pending := validTunnelProfile(3, now)
	previous := validTunnelProfile(1, now)
	previous.ProtocolVersion = clienttunnel.ProtocolAmneziaWG3
	tests := []LifecycleRequest{
		{
			Action:                 LifecycleActionStage,
			ProtocolVersion:        clienttunnel.ProtocolAmneziaWG3,
			ExpectedActiveRevision: &stale,
		},
		{
			Action:                 LifecycleActionActivate,
			TargetRevision:         uint64TestPointer(3),
			ExpectedActiveRevision: &stale,
		},
		{
			Action:                 LifecycleActionCancelPending,
			TargetRevision:         uint64TestPointer(3),
			ExpectedActiveRevision: &stale,
		},
		{
			Action:                 LifecycleActionRollback,
			TargetRevision:         uint64TestPointer(1),
			ExpectedActiveRevision: &stale,
		},
		{
			Action:                 LifecycleActionSetPolicy,
			Policy:                 types.TunnelAccountPolicyPreferAWG,
			ExpectedActiveRevision: &stale,
		},
	}
	for _, request := range tests {
		t.Run(string(request.Action), func(t *testing.T) {
			_, _, err := ApplyLifecycle(
				&types.Settings{
					TunnelPolicy:            types.TunnelAccountPolicyStandard,
					TunnelProfile:           active,
					TunnelProfilePending:    pending,
					TunnelProfilePrevious:   previous,
					TunnelProfileGraceUntil: now.Add(time.Hour),
				},
				request,
				Readiness{State: ReadinessReady},
				now,
			)
			var lifecycleErr *LifecycleError
			if !errors.As(err, &lifecycleErr) ||
				lifecycleErr.Code != LifecycleErrorStaleActiveRevision {
				t.Fatalf("stale expectation error = %v", err)
			}
		})
	}
}

func TestApplyLifecycleMapsExpiredRollbackToUnavailable(t *testing.T) {
	now := time.Now().UTC()
	target := uint64(1)
	_, _, err := ApplyLifecycle(
		&types.Settings{
			TunnelProfilePrevious:   validTunnelProfile(target, now.Add(-time.Hour)),
			TunnelProfileGraceUntil: now,
		},
		LifecycleRequest{
			Action:         LifecycleActionRollback,
			TargetRevision: &target,
		},
		Readiness{},
		now,
	)
	var lifecycleErr *LifecycleError
	if !errors.As(err, &lifecycleErr) ||
		lifecycleErr.Code != LifecycleErrorRollbackUnavailable {
		t.Fatalf("expired rollback error = %v", err)
	}
}

func TestApplyLifecycleRejectsZeroTargetRevision(t *testing.T) {
	zero := uint64(0)
	_, _, err := ApplyLifecycle(
		&types.Settings{},
		LifecycleRequest{
			Action:         LifecycleActionActivate,
			TargetRevision: &zero,
		},
		Readiness{},
		time.Now().UTC(),
	)
	var lifecycleErr *LifecycleError
	if !errors.As(err, &lifecycleErr) ||
		lifecycleErr.Code != LifecycleErrorInvalidRequest {
		t.Fatalf("zero target error = %v", err)
	}
}

func uint64TestPointer(value uint64) *uint64 {
	return &value
}

func lifecyclePeer(
	id string,
	profile *types.TunnelProfile,
	now time.Time,
	ready bool,
	errorCode string,
) *sharedtypes.ComponentPeer {
	return &sharedtypes.ComponentPeer{
		ID:                 id,
		SupportsHybridAWG2: true,
		TunnelRuntime: sharedtypes.TunnelRuntimeInfo{
			ProtocolVersion: clienttunnel.ProtocolAmneziaWG2,
			ProfileRevision: profile.Revision,
			AdapterRevision: HybridAWG2AdapterRevision,
			Ready:           ready,
			ErrorCode:       errorCode,
			UpdatedAt:       now,
		},
	}
}
