package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (am *DefaultAccountManager) updateEmbeddedUserPassword(ctx context.Context, accountID, currentUserID, targetUserID string, oldPassword, newPassword string) error {
	if !IsEmbeddedIdp(am.idpManager) {
		return status.Errorf(status.PreconditionFailed, "password change is only available with embedded identity provider")
	}
	if err := validatePassword(newPassword); err != nil {
		return status.Errorf(status.InvalidArgument, "invalid new password: %v", err)
	}

	targetUser, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, targetUserID)
	if err != nil {
		return err
	}
	if targetUser.AccountID != accountID {
		return status.NewUserNotFoundError(targetUserID)
	}

	embeddedIdp, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return status.Errorf(status.Internal, "failed to get embedded IdP manager")
	}
	supported, err := embeddedIdp.SupportsUserPasswordManagement(ctx, targetUser.Id)
	if err != nil {
		return status.Errorf(status.PreconditionFailed, "failed to determine password management capability: %v", err)
	}
	if !supported {
		return status.Errorf(status.PreconditionFailed, "password is managed by the external identity provider")
	}

	if currentUserID == targetUserID {
		if err := am.changeOwnEmbeddedPassword(ctx, embeddedIdp, targetUser, oldPassword, newPassword); err != nil {
			return err
		}
	} else if err := am.resetEmbeddedUserPassword(ctx, embeddedIdp, accountID, currentUserID, targetUser, newPassword); err != nil {
		return err
	}

	am.StoreEvent(ctx, currentUserID, targetUserID, accountID, activity.UserPasswordChanged, nil)
	return nil
}

func (am *DefaultAccountManager) changeOwnEmbeddedPassword(ctx context.Context, embeddedIdp *idp.EmbeddedIdPManager, targetUser *types.User, oldPassword, newPassword string) error {
	if oldPassword == "" {
		return status.Errorf(status.InvalidArgument, "old password is required")
	}
	if oldPassword == newPassword {
		return status.Errorf(status.InvalidArgument, "new password must differ from the current password")
	}
	if err := embeddedIdp.UpdateUserPassword(ctx, targetUser.Id, targetUser.Id, oldPassword, newPassword); err != nil {
		return status.Errorf(status.InvalidArgument, "failed to update password: %v", err)
	}

	targetUser.ForcePasswordChange = false
	if err := am.Store.SaveUser(ctx, targetUser); err != nil {
		return status.Errorf(status.Internal, "password changed but failed to clear forced password change state")
	}
	return nil
}

func (am *DefaultAccountManager) resetEmbeddedUserPassword(ctx context.Context, embeddedIdp *idp.EmbeddedIdPManager, accountID, currentUserID string, targetUser *types.User, newPassword string) error {
	if targetUser.Role == types.UserRoleOwner {
		return status.Errorf(status.PermissionDenied, "only the owner can change the owner password")
	}
	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, currentUserID, modules.Users, operations.Update)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	// Save the forced-change state first. If the external reset fails, retaining
	// this flag is the fail-safe result.
	targetUser.ForcePasswordChange = true
	if err := am.Store.SaveUser(ctx, targetUser); err != nil {
		return status.Errorf(status.Internal, "failed to require a password change before resetting password")
	}
	if err := embeddedIdp.ResetUserPassword(ctx, targetUser.Id, newPassword); err != nil {
		return status.Errorf(status.InvalidArgument, "failed to reset password: %v", err)
	}
	if err := am.invalidateEmbeddedUserAccess(ctx, embeddedIdp, accountID, targetUser.Id); err != nil {
		return status.Errorf(status.Internal, "password reset but failed to invalidate existing access: %v", err)
	}
	return nil
}

// invalidateEmbeddedUserAccess revokes browser/refresh sessions and expires
// every SSO peer owned by the user. Both branches are attempted so a failure in
// one revocation mechanism never prevents the other fail-closed action.
func (am *DefaultAccountManager) invalidateEmbeddedUserAccess(ctx context.Context, embeddedIdp *idp.EmbeddedIdPManager, accountID, userID string) error {
	var invalidationErr error
	if err := embeddedIdp.RevokeUserSessions(ctx, userID); err != nil {
		invalidationErr = errors.Join(invalidationErr, fmt.Errorf("revoke identity sessions: %w", err))
	}

	peers, err := am.Store.GetUserPeers(ctx, store.LockingStrengthNone, accountID, userID)
	if err != nil {
		invalidationErr = errors.Join(invalidationErr, fmt.Errorf("load user peers: %w", err))
	} else if len(peers) > 0 {
		peerIDs := make([]string, 0, len(peers))
		for _, peer := range peers {
			if peer.UserID != "" {
				peerIDs = append(peerIDs, peer.ID)
			}
		}
		// Disconnect first. The persisted ForcePasswordChange/Blocked state
		// prevents a reconnect even if the status/network-map update below fails.
		am.networkMapController.DisconnectPeers(ctx, accountID, peerIDs)
		if err := am.expireAndUpdatePeers(ctx, accountID, peers, peerExpirationUserBlocked); err != nil {
			invalidationErr = errors.Join(invalidationErr, fmt.Errorf("expire user peers: %w", err))
		}
	}

	return invalidationErr
}
