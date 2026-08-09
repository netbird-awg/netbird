package tunnel

import (
	"errors"
	"fmt"
	"time"

	clienttunnel "github.com/netbirdio/netbird/client/iface/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

// LifecycleAction identifies a tunnel profile lifecycle transition.
type LifecycleAction string

const (
	LifecycleActionStage         LifecycleAction = "stage"
	LifecycleActionActivate      LifecycleAction = "activate"
	LifecycleActionCancelPending LifecycleAction = "cancel_pending"
	LifecycleActionRollback      LifecycleAction = "rollback"
	LifecycleActionSetPolicy     LifecycleAction = "set_policy"
)

// LifecycleErrorCode is a stable machine-readable lifecycle error code.
type LifecycleErrorCode string

const (
	LifecycleErrorInvalidRequest       LifecycleErrorCode = "invalid_request"
	LifecycleErrorStaleActiveRevision  LifecycleErrorCode = "stale_active_revision"
	LifecycleErrorStalePendingRevision LifecycleErrorCode = "stale_pending_revision"
	LifecycleErrorStaleTargetRevision  LifecycleErrorCode = "stale_target_revision"
	LifecycleErrorNotReady             LifecycleErrorCode = "not_ready"
	LifecycleErrorRollbackUnavailable  LifecycleErrorCode = "rollback_unavailable"
	LifecycleErrorTransitionRejected   LifecycleErrorCode = "transition_rejected"
)

// LifecycleError describes a stable lifecycle failure without peer details.
type LifecycleError struct {
	Code    LifecycleErrorCode
	Message string
}

func (e *LifecycleError) Error() string {
	return e.Message
}

// NewLifecycleError constructs a typed lifecycle error.
func NewLifecycleError(code LifecycleErrorCode, message string) error {
	return &LifecycleError{Code: code, Message: message}
}

// LifecycleRequest contains only client-controlled lifecycle inputs.
type LifecycleRequest struct {
	Action                  LifecycleAction
	ProtocolVersion         string
	Policy                  types.TunnelAccountPolicy
	TargetRevision          *uint64
	ExpectedActiveRevision  *uint64
	ExpectedPendingRevision *uint64
}

// ReadinessState describes whether a pending profile can be activated.
type ReadinessState string

const (
	ReadinessNotStaged ReadinessState = "not_staged"
	ReadinessReady     ReadinessState = "ready"
	ReadinessWaiting   ReadinessState = "waiting"
)

// Readiness is a privacy-safe aggregate of pending profile readiness.
type Readiness struct {
	State           ReadinessState
	Eligible        int
	Ready           int
	Waiting         int
	ExcludedOffline int
	Incompatible    int
	PendingRevision *uint64
	ObservedAt      time.Time
	ErrorCounts     map[string]int
}

// LifecycleResult is a tunnel-only snapshot returned by the manager.
type LifecycleResult struct {
	Settings  *types.Settings
	Readiness Readiness
	Changed   bool
}

// EvaluateReadiness computes the aggregate used by both GET and activation.
func EvaluateReadiness(
	pending *types.TunnelProfile,
	eligible []*sharedtypes.ComponentPeer,
	excludedOffline,
	incompatible int,
	observedAt time.Time,
) Readiness {
	result := Readiness{
		State:           ReadinessNotStaged,
		Eligible:        len(eligible),
		ExcludedOffline: excludedOffline,
		Incompatible:    incompatible,
		ObservedAt:      observedAt,
		ErrorCounts:     map[string]int{},
	}
	if pending == nil {
		return result
	}
	revision := pending.Revision
	result.PendingRevision = &revision
	result.State = ReadinessReady
	for _, peer := range eligible {
		state := plannerPeerState(peer, UserPolicyInherit, pending)
		if state.Ready && configurationMismatchReason(state, state) == "" {
			result.Ready++
			continue
		}
		result.Waiting++
		result.ErrorCounts[readinessErrorCode(peer, state)]++
	}
	if result.Waiting > 0 {
		result.State = ReadinessWaiting
	}
	return result
}

func readinessErrorCode(
	peer *sharedtypes.ComponentPeer,
	state PeerState,
) string {
	if code := sharedtypes.NormalizeTunnelRuntimeErrorCode(
		peer.TunnelRuntime.ErrorCode,
	); code != "" {
		return code
	}
	if !state.AdapterCompatible {
		return sharedtypes.TunnelReadinessErrorAdapterIncompatible
	}
	if state.ProtocolVersion != state.AssignedProtocol {
		return sharedtypes.TunnelReadinessErrorProtocolMismatch
	}
	if state.AssignedRevision == 0 ||
		state.ProfileRevision != state.AssignedRevision {
		return sharedtypes.TunnelReadinessErrorRevisionMismatch
	}
	return sharedtypes.TunnelReadinessErrorNotReady
}

// ApplyLifecycle applies one validated request to a tunnel settings copy.
func ApplyLifecycle(
	current *types.Settings,
	request LifecycleRequest,
	readiness Readiness,
	now time.Time,
) (*types.Settings, bool, error) {
	if current == nil {
		return nil, false, errors.New("tunnel settings are nil")
	}
	if err := validateLifecycleRequest(request); err != nil {
		return nil, false, err
	}
	updated := current.Copy()
	if isTerminalLifecycleReplay(current, request) {
		return updated, false, nil
	}
	if err := validateExpectedRevisions(current, request); err != nil {
		return nil, false, err
	}
	switch request.Action {
	case LifecycleActionStage:
		updated.TunnelProfile = &types.TunnelProfile{
			ProtocolVersion: request.ProtocolVersion,
		}
	case LifecycleActionActivate:
		if current.TunnelProfilePending == nil ||
			current.TunnelProfilePending.Revision != *request.TargetRevision {
			return nil, false, NewLifecycleError(
				LifecycleErrorStaleTargetRevision,
				"target tunnel revision is stale",
			)
		}
		if readiness.State != ReadinessReady {
			return nil, false, NewLifecycleError(
				LifecycleErrorNotReady,
				"pending tunnel profile is not ready",
			)
		}
		updated.TunnelProfileAction = types.TunnelProfileActionActivate
	case LifecycleActionCancelPending:
		if current.TunnelProfilePending == nil {
			return updated, false, nil
		}
		if request.TargetRevision == nil {
			return nil, false, NewLifecycleError(
				LifecycleErrorInvalidRequest,
				"target_revision is required for cancel_pending",
			)
		}
		if current.TunnelProfilePending.Revision != *request.TargetRevision {
			return nil, false, NewLifecycleError(
				LifecycleErrorStaleTargetRevision,
				"target tunnel revision is stale",
			)
		}
		if request.Policy != "" {
			updated.TunnelPolicy = request.Policy
		}
		updated.TunnelProfileAction = types.TunnelProfileActionCancelPending
	case LifecycleActionRollback:
		if current.TunnelProfilePrevious == nil ||
			current.TunnelProfilePrevious.Revision != *request.TargetRevision ||
			current.TunnelProfileGraceUntil.IsZero() ||
			!current.TunnelProfileGraceUntil.After(now) {
			return nil, false, NewLifecycleError(
				LifecycleErrorRollbackUnavailable,
				"requested rollback profile is unavailable",
			)
		}
		updated.TunnelProfileAction = types.TunnelProfileActionRollback
	case LifecycleActionSetPolicy:
		updated.TunnelPolicy = request.Policy
	default:
		return nil, false, NewLifecycleError(
			LifecycleErrorInvalidRequest,
			fmt.Sprintf("unsupported lifecycle action %q", request.Action),
		)
	}

	changed, err := PrepareSettingsUpdate(updated, current, now, nil)
	if err != nil {
		return nil, false, NewLifecycleError(
			LifecycleErrorTransitionRejected,
			"tunnel lifecycle transition was rejected",
		)
	}
	return updated, changed, nil
}

func validateLifecycleRequest(request LifecycleRequest) error {
	if request.TargetRevision != nil && *request.TargetRevision == 0 {
		return NewLifecycleError(
			LifecycleErrorInvalidRequest,
			"target_revision must be greater than zero",
		)
	}
	switch request.Action {
	case LifecycleActionStage:
		if request.ProtocolVersion != clienttunnel.ProtocolAmneziaWG2 &&
			request.ProtocolVersion != clienttunnel.ProtocolAmneziaWG3 ||
			request.Policy != "" || request.TargetRevision != nil {
			return NewLifecycleError(
				LifecycleErrorInvalidRequest,
				"protocol_version is required for stage",
			)
		}
	case LifecycleActionActivate, LifecycleActionRollback:
		if request.TargetRevision == nil || request.ProtocolVersion != "" ||
			request.Policy != "" {
			return NewLifecycleError(
				LifecycleErrorInvalidRequest,
				"target_revision is required for action",
			)
		}
	case LifecycleActionCancelPending:
		if request.ProtocolVersion != "" ||
			request.Policy != "" && !validAccountPolicy(request.Policy) {
			return NewLifecycleError(
				LifecycleErrorInvalidRequest,
				"unsupported policy",
			)
		}
	case LifecycleActionSetPolicy:
		if !validAccountPolicy(request.Policy) ||
			request.ProtocolVersion != "" || request.TargetRevision != nil {
			return NewLifecycleError(
				LifecycleErrorInvalidRequest,
				"policy is required for set_policy",
			)
		}
	default:
		return NewLifecycleError(
			LifecycleErrorInvalidRequest,
			fmt.Sprintf("unsupported lifecycle action %q", request.Action),
		)
	}
	return nil
}

func isTerminalLifecycleReplay(
	current *types.Settings,
	request LifecycleRequest,
) bool {
	switch request.Action {
	case LifecycleActionStage:
		return current.TunnelProfilePending != nil &&
			current.TunnelProfilePending.ProtocolVersion == request.ProtocolVersion
	case LifecycleActionActivate:
		return current.TunnelProfile != nil &&
			current.TunnelProfile.Revision == *request.TargetRevision &&
			current.TunnelProfilePending == nil
	case LifecycleActionCancelPending:
		return current.TunnelProfilePending == nil
	case LifecycleActionRollback:
		return current.TunnelProfilePrevious != nil &&
			current.TunnelProfilePrevious.Revision == *request.TargetRevision &&
			current.TunnelProfilePending != nil &&
			sameProfileContents(
				current.TunnelProfilePending,
				current.TunnelProfilePrevious,
			)
	case LifecycleActionSetPolicy:
		return current.TunnelPolicy == request.Policy
	default:
		return false
	}
}

func validateExpectedRevisions(
	current *types.Settings,
	request LifecycleRequest,
) error {
	if request.ExpectedActiveRevision != nil &&
		profileRevision(current.TunnelProfile) != *request.ExpectedActiveRevision {
		return NewLifecycleError(
			LifecycleErrorStaleActiveRevision,
			"active tunnel revision changed",
		)
	}
	if request.ExpectedPendingRevision != nil &&
		profileRevision(current.TunnelProfilePending) != *request.ExpectedPendingRevision {
		return NewLifecycleError(
			LifecycleErrorStalePendingRevision,
			"pending tunnel revision changed",
		)
	}
	return nil
}

func profileRevision(profile *types.TunnelProfile) uint64 {
	if profile == nil {
		return 0
	}
	return profile.Revision
}
