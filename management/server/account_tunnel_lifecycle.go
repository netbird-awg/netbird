package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	managementtunnel "github.com/netbirdio/netbird/management/server/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

// GetTunnelLifecycle returns a privacy-safe tunnel lifecycle snapshot.
func (am *DefaultAccountManager) GetTunnelLifecycle(
	ctx context.Context,
	accountID,
	userID string,
) (*managementtunnel.LifecycleResult, error) {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(
		ctx,
		accountID,
		userID,
		modules.Settings,
		operations.Read,
	)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}
	return am.getTunnelLifecycleWithClock(ctx, accountID, time.Now)
}

func (am *DefaultAccountManager) getTunnelLifecycleWithClock(
	ctx context.Context,
	accountID string,
	clock func() time.Time,
) (*managementtunnel.LifecycleResult, error) {
	var result *managementtunnel.LifecycleResult
	err := am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		settings, err := transaction.GetAccountSettings(
			ctx,
			store.LockingStrengthShare,
			accountID,
		)
		if err != nil {
			return err
		}
		peers, err := transaction.GetAccountPeers(
			ctx,
			store.LockingStrengthNone,
			accountID,
			"",
			"",
		)
		if err != nil {
			return fmt.Errorf("get tunnel readiness peers: %w", err)
		}
		now := clock().UTC()
		eligible, excludedOffline, incompatible := tunnelReadinessPeers(
			peers,
			settings.TunnelProfilePending,
			now,
		)
		result = &managementtunnel.LifecycleResult{
			Settings: settings,
			Readiness: managementtunnel.EvaluateReadiness(
				settings.TunnelProfilePending,
				eligible,
				excludedOffline,
				incompatible,
				now,
			),
		}
		return nil
	})
	return result, err
}

// UpdateTunnelLifecycle applies one tunnel-only transition transactionally.
func (am *DefaultAccountManager) UpdateTunnelLifecycle(
	ctx context.Context,
	accountID,
	userID string,
	request managementtunnel.LifecycleRequest,
) (*managementtunnel.LifecycleResult, error) {
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(
		ctx,
		accountID,
		userID,
		modules.Settings,
		operations.Update,
	)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	result, err := am.updateTunnelLifecycleWithClock(
		ctx,
		accountID,
		request,
		time.Now,
	)
	if err != nil || !result.Changed {
		return result, err
	}
	am.publishTunnelLifecycleChange(
		ctx,
		accountID,
		userID,
		request,
		result.Settings,
	)
	return result, nil
}

func (am *DefaultAccountManager) publishTunnelLifecycleChange(
	ctx context.Context,
	accountID,
	userID string,
	request managementtunnel.LifecycleRequest,
	settings *types.Settings,
) {
	postCommitCtx := context.WithoutCancel(ctx)
	am.StoreEvent(
		postCommitCtx,
		userID,
		accountID,
		accountID,
		activity.AccountTunnelPolicyUpdated,
		map[string]any{
			"action":           request.Action,
			"active_revision":  tunnelProfileRevision(settings.TunnelProfile),
			"pending_revision": tunnelProfileRevision(settings.TunnelProfilePending),
		},
	)
	go am.UpdateAccountPeers(
		postCommitCtx,
		accountID,
		types.UpdateReason{
			Resource:  types.UpdateResourceAccountSettings,
			Operation: types.UpdateOperationUpdate,
		},
	)
}

func (am *DefaultAccountManager) updateTunnelLifecycleWithClock(
	ctx context.Context,
	accountID string,
	request managementtunnel.LifecycleRequest,
	clock func() time.Time,
) (*managementtunnel.LifecycleResult, error) {
	var result *managementtunnel.LifecycleResult
	err := am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		current, err := transaction.GetAccountSettings(
			ctx,
			store.LockingStrengthUpdate,
			accountID,
		)
		if err != nil {
			return err
		}
		peers, err := transaction.GetAccountPeers(
			ctx,
			store.LockingStrengthNone,
			accountID,
			"",
			"",
		)
		if err != nil {
			return fmt.Errorf("get tunnel readiness peers: %w", err)
		}
		now := clock().UTC()
		eligible, excludedOffline, incompatible := tunnelReadinessPeers(
			peers,
			current.TunnelProfilePending,
			now,
		)
		readiness := managementtunnel.EvaluateReadiness(
			current.TunnelProfilePending,
			eligible,
			excludedOffline,
			incompatible,
			now,
		)
		updated, changed, err := managementtunnel.ApplyLifecycle(
			current,
			request,
			readiness,
			now,
		)
		if err != nil {
			var lifecycleErr *managementtunnel.LifecycleError
			if errors.As(err, &lifecycleErr) {
				return err
			}
			return fmt.Errorf("apply tunnel lifecycle: %w", err)
		}
		if changed {
			if err := transaction.SaveAccountSettings(
				ctx,
				accountID,
				updated,
			); err != nil {
				return err
			}
			if err := transaction.IncrementNetworkSerial(
				ctx,
				accountID,
			); err != nil {
				return err
			}
		}
		eligible, excludedOffline, incompatible = tunnelReadinessPeers(
			peers,
			updated.TunnelProfilePending,
			now,
		)
		result = &managementtunnel.LifecycleResult{
			Settings: updated,
			Changed:  changed,
			Readiness: managementtunnel.EvaluateReadiness(
				updated.TunnelProfilePending,
				eligible,
				excludedOffline,
				incompatible,
				now,
			),
		}
		return nil
	})
	return result, err
}

func tunnelReadinessPeers(
	peers []*nbpeer.Peer,
	pending *types.TunnelProfile,
	now time.Time,
) ([]*sharedtypes.ComponentPeer, int, int) {
	eligible := make([]*sharedtypes.ComponentPeer, 0, len(peers))
	var excludedOffline int
	var incompatible int
	for _, peer := range peers {
		if peer == nil ||
			(!peer.SupportsHybridAmneziaWG2() &&
				!peer.SupportsHybridAmneziaWG3()) {
			incompatible++
			continue
		}
		if !tunnelProfileActivationPeerEligible(peer, pending, now) {
			excludedOffline++
			continue
		}
		eligible = append(eligible, peer.ToComponent())
	}
	return eligible, excludedOffline, incompatible
}
