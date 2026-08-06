package server

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (am *DefaultAccountManager) applyExternalPreRegistration(ctx context.Context, accountID string, userAuth auth.UserAuth, newUser *types.User) bool {
	preRegistration, err := am.Store.GetUserInviteByEmail(ctx, store.LockingStrengthNone, accountID, userAuth.Email)
	if err != nil {
		if statusErr, ok := status.FromError(err); !ok || statusErr.Type() != status.NotFound {
			log.WithContext(ctx).Warnf("failed to check pre-registration for %s: %v", userAuth.Email, err)
		}
		return false
	}
	if preRegistration == nil || preRegistration.IdpID == "" {
		return false
	}

	newUser.Role = types.StrRoleToUserRole(preRegistration.Role)
	newUser.AutoGroups = preRegistration.AutoGroups
	newUser.Name = preRegistration.Name
	if err := am.Store.DeleteUserInvite(ctx, preRegistration.ID); err != nil {
		log.WithContext(ctx).Warnf("failed to delete pre-registration %s: %v", preRegistration.ID, err)
	}
	log.WithContext(ctx).Infof("auto-approved pre-registered external IDP user %s (email: %s, idp: %s)", userAuth.UserId, userAuth.Email, preRegistration.IdpID)
	return true
}

// checkLDAPGroupRestriction verifies required LDAP groups from the signed token
// claims on every JWT authentication path. This avoids a directory round trip
// on every API request while ensuring existing users cannot bypass the policy.
func (am *DefaultAccountManager) checkLDAPGroupRestriction(ctx context.Context, accountID string, userAuth auth.UserAuth) error {
	if userAuth.IsPAT {
		return nil
	}
	embeddedIdp, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return nil
	}

	_, connectorID, externalUser := decodeExternalDexUserID(userAuth.UserId)
	if !externalUser {
		return nil
	}
	conn, err := embeddedIdp.GetConnector(ctx, connectorID)
	if err != nil {
		log.WithContext(ctx).WithError(err).Warnf("failed to resolve LDAP connector %s", connectorID)
		return status.Errorf(status.PermissionDenied, "failed to verify LDAP login policy")
	}
	if accountID != "" {
		visible, err := am.ensureIdentityProviderAccount(ctx, embeddedIdp, accountID, conn)
		if err != nil || !visible {
			return status.Errorf(status.PermissionDenied, "failed to verify LDAP login policy")
		}
	}
	if conn.Type != "ldap" || conn.LDAP == nil || len(conn.LDAP.RequiredGroups) == 0 {
		return nil
	}

	for _, required := range conn.LDAP.RequiredGroups {
		for _, actual := range userAuth.Groups {
			if strings.EqualFold(strings.TrimSpace(required), strings.TrimSpace(actual)) {
				return nil
			}
		}
	}
	log.WithContext(ctx).Infof("LDAP user %s is not a member of required groups %v, login denied", userAuth.UserId, conn.LDAP.RequiredGroups)
	return status.Errorf(status.PermissionDenied, "user is not a member of the required LDAP groups: %v", conn.LDAP.RequiredGroups)
}

// createExternalIdpPreRegistration provisions an LDAP user and records it in NetBird.
func (am *DefaultAccountManager) createExternalIdpPreRegistration(ctx context.Context, accountID, initiatorUserID string, invite *types.UserInfo) (*types.UserInvite, error) {
	if err := validateUserInvite(invite); err != nil {
		return nil, err
	}
	if invite.Password == "" {
		return nil, status.Errorf(status.InvalidArgument, "password is required when creating an external IDP user")
	}
	if err := validatePassword(invite.Password); err != nil {
		return nil, status.Errorf(status.InvalidArgument, "invalid password: %v", err)
	}

	allowed, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, initiatorUserID, modules.Users, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	embeddedIdp, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return nil, status.Errorf(status.Internal, "failed to get embedded IdP manager")
	}
	conn, err := am.getIdentityProviderConnector(ctx, embeddedIdp, accountID, invite.IdPID)
	if err != nil {
		return nil, status.Errorf(status.InvalidArgument, "identity provider connector %q not found", invite.IdPID)
	}
	if conn.Type != "ldap" || conn.LDAP == nil {
		return nil, status.Errorf(status.InvalidArgument, "connector %q is not an LDAP identity provider (type: %s)", invite.IdPID, conn.Type)
	}
	if strings.TrimSpace(conn.LDAP.GroupSearchBaseDN) == "" {
		return nil, status.Errorf(status.InvalidArgument, "LDAP group search base DN is required to assign users to the %q group", types.DefaultLDAPUserGroup)
	}
	invite.LdapGroups = types.NormalizeLDAPUserGroups(invite.LdapGroups)

	if err := am.ensureExternalUserDoesNotExist(ctx, accountID, invite.Email); err != nil {
		return nil, err
	}
	if err := dex.CreateLDAPUser(conn.LDAP, invite.Email, invite.Password, invite.Name); err != nil {
		return nil, status.Errorf(status.Internal, "failed to create user in LDAP: %v", err)
	}
	ldapUser, err := dex.FindLDAPUserByEmail(conn.LDAP, invite.Email)
	if err != nil {
		rollbackLDAPUser(ctx, conn.LDAP, invite.Email)
		return nil, status.Errorf(status.Internal, "failed to resolve the created LDAP user: %v", err)
	}

	if err := dex.AddUserToLDAPGroups(conn.LDAP, invite.Email, invite.LdapGroups); err != nil {
		log.WithContext(ctx).WithError(err).Errorf("failed to add LDAP user %s to groups %v", invite.Email, invite.LdapGroups)
		rollbackLDAPUser(ctx, conn.LDAP, invite.Email)
		return nil, status.Errorf(status.Internal, "failed to assign LDAP user groups")
	}

	dexUserID := dex.EncodeDexUserID(ldapUser.StableID, invite.IdPID)
	newUser := types.NewUser(dexUserID, types.StrRoleToUserRole(invite.Role), false, false, "", invite.AutoGroups, types.UserIssuedAPI, invite.Email, invite.Name)
	newUser.AccountID = accountID
	newUser.ForcePasswordChange = invite.ForcePasswordChange

	if err := am.Store.SaveUser(ctx, newUser); err != nil {
		rollbackLDAPUser(ctx, conn.LDAP, invite.Email)
		return nil, status.Errorf(status.Internal, "failed to save user record: %v", err)
	}

	am.StoreEvent(ctx, initiatorUserID, dexUserID, accountID, activity.UserJoined, map[string]any{
		"email": invite.Email, "idp_id": invite.IdPID, "ldap_groups": invite.LdapGroups,
	})
	return externalUserInviteResult(invite, dexUserID), nil
}

func rollbackLDAPUser(ctx context.Context, config *dex.LDAPConnectorConfig, email string) {
	if err := dex.RemoveUserFromLDAPGroups(config, email); err != nil {
		log.WithContext(ctx).WithError(err).Errorf("failed to rollback LDAP group membership for %s", email)
	}
	if err := dex.DeleteLDAPUser(config, email); err != nil {
		log.WithContext(ctx).WithError(err).Errorf("failed to rollback LDAP user %s", email)
	}
}

// deleteLDAPDirectoryUser removes an embedded-Dex LDAP user from the upstream
// directory before the NetBird record is deleted. Returning true prevents the
// generic embedded IdP deletion path from treating the LDAP subject as a local
// Dex password user.
func (am *DefaultAccountManager) deleteLDAPDirectoryUser(ctx context.Context, accountID string, targetUser *types.UserInfo) (bool, error) {
	embeddedIdp, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok || targetUser == nil {
		return false, nil
	}

	stableID, connectorID, externalUser := decodeExternalDexUserID(targetUser.ID)
	if !externalUser {
		return false, nil
	}

	connector, err := am.getIdentityProviderConnector(ctx, embeddedIdp, accountID, connectorID)
	if err != nil {
		log.WithContext(ctx).WithError(err).Errorf("failed to resolve identity provider connector %s while deleting user %s", connectorID, targetUser.ID)
		return false, status.Errorf(status.Internal, "failed to resolve user identity provider")
	}
	if connector.Type != "ldap" || connector.LDAP == nil {
		return false, nil
	}
	target, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthNone, targetUser.ID)
	if err != nil {
		return true, status.Errorf(status.Internal, "failed to prepare LDAP directory deletion")
	}
	if target.AccountID != accountID {
		return true, status.NewUserNotFoundError(targetUser.ID)
	}
	if !target.DirectoryDeletionPending || !target.Blocked {
		target.DirectoryDeletionPending = true
		target.Blocked = true
		target.LDAPSyncBlocked = false
		if err := am.Store.SaveUser(ctx, target); err != nil {
			return true, status.Errorf(status.Internal, "failed to persist LDAP directory deletion state")
		}
	}
	if err := am.invalidateEmbeddedUserAccess(ctx, embeddedIdp, accountID, target.Id); err != nil {
		log.WithContext(ctx).WithError(err).Errorf("failed to invalidate access before deleting LDAP directory user %s", targetUser.ID)
		return true, status.Errorf(status.Internal, "failed to invalidate user access before LDAP directory deletion")
	}

	if err := dex.DeleteLDAPDirectoryUser(connector.LDAP, stableID); err != nil {
		log.WithContext(ctx).WithError(err).Errorf("failed to delete LDAP directory user %s", targetUser.ID)
		return true, status.Errorf(status.Internal, "failed to delete user from LDAP directory")
	}

	log.WithContext(ctx).Infof("deleted LDAP directory user %s using connector %s", targetUser.ID, connectorID)
	return true, nil
}

func decodeExternalDexUserID(userID string) (string, string, bool) {
	stableID, connectorID, err := dex.DecodeDexUserID(userID)
	if err != nil || connectorID == "" || connectorID == "local" {
		return "", "", false
	}
	return stableID, connectorID, true
}

func (am *DefaultAccountManager) ensureExternalUserDoesNotExist(ctx context.Context, accountID, email string) error {
	existingUsers, err := am.Store.GetAccountUsers(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return err
	}
	for _, user := range existingUsers {
		if strings.EqualFold(user.Email, email) {
			return status.Errorf(status.UserAlreadyExists, "user with this email already exists")
		}
	}

	existingInvite, err := am.Store.GetUserInviteByEmail(ctx, store.LockingStrengthNone, accountID, email)
	if err != nil {
		if statusErr, ok := status.FromError(err); !ok || statusErr.Type() != status.NotFound {
			return fmt.Errorf("failed to check existing invites: %w", err)
		}
	}
	if existingInvite != nil {
		return status.Errorf(status.AlreadyExists, "a pre-registration or invite already exists for this email")
	}
	return nil
}

func externalUserInviteResult(invite *types.UserInfo, dexUserID string) *types.UserInvite {
	return &types.UserInvite{UserInfo: &types.UserInfo{
		ID: dexUserID, Email: invite.Email, Name: invite.Name, Role: invite.Role,
		AutoGroups: invite.AutoGroups, Status: string(types.UserStatusActive),
		Issued: types.UserIssuedAPI, IdPID: invite.IdPID,
	}}
}
