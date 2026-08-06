package server

import (
	"context"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ListLDAPGroups returns all LDAP group names for the specified LDAP identity provider.
func (am *DefaultAccountManager) ListLDAPGroups(ctx context.Context, accountID, idpID, userID string) ([]string, error) {
	ok, ctx, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.IdentityProviders, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	embeddedManager, ok := am.idpManager.(*idp.EmbeddedIdPManager)
	if !ok {
		return nil, status.Errorf(status.Internal, "identity provider management requires embedded IdP")
	}

	conn, err := am.getIdentityProviderConnector(ctx, embeddedManager, accountID, idpID)
	if err != nil {
		return nil, status.Errorf(status.NotFound, "identity provider %q not found", idpID)
	}
	if conn.Type != "ldap" || conn.LDAP == nil {
		return nil, status.Errorf(status.InvalidArgument, "identity provider %q is not LDAP type", idpID)
	}

	groups, err := dex.ListLDAPGroups(conn.LDAP)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to list LDAP groups: %v", err)
	}
	return groups, nil
}

func applyLDAPConnectorConfig(identityProvider *types.IdentityProvider, ldap *dex.LDAPConnectorConfig) {
	if ldap == nil {
		return
	}
	identityProvider.LDAPHost = ldap.Host
	identityProvider.LDAPInsecureNoSSL = ldap.InsecureNoSSL
	identityProvider.LDAPInsecureSkipVerify = ldap.InsecureSkipVerify
	identityProvider.LDAPStartTLS = ldap.StartTLS
	identityProvider.LDAPRootCA = ldap.RootCA
	identityProvider.LDAPBindDN = ldap.BindDN
	identityProvider.LDAPBindPW = ldap.BindPW
	identityProvider.LDAPUserSearchBaseDN = ldap.UserSearchBaseDN
	identityProvider.LDAPUserSearchFilter = ldap.UserSearchFilter
	identityProvider.LDAPUserSearchUsername = ldap.UserSearchUsername
	identityProvider.LDAPUserSearchIDAttr = ldap.UserSearchIDAttr
	identityProvider.LDAPUserSearchEmailAttr = ldap.UserSearchEmailAttr
	identityProvider.LDAPUserSearchNameAttr = ldap.UserSearchNameAttr
	identityProvider.LDAPGroupSearchBaseDN = ldap.GroupSearchBaseDN
	identityProvider.LDAPGroupSearchFilter = ldap.GroupSearchFilter
	identityProvider.LDAPGroupSearchUserAttr = ldap.GroupSearchUserAttr
	identityProvider.LDAPGroupSearchGroupAttr = ldap.GroupSearchGroupAttr
	identityProvider.LDAPGroupSearchNameAttr = ldap.GroupSearchNameAttr
	identityProvider.SetRequiredGroups(ldap.RequiredGroups)
}

func identityProviderLDAPConnectorConfig(identityProvider *types.IdentityProvider) *dex.LDAPConnectorConfig {
	return &dex.LDAPConnectorConfig{
		Host:                 identityProvider.LDAPHost,
		InsecureNoSSL:        identityProvider.LDAPInsecureNoSSL,
		InsecureSkipVerify:   identityProvider.LDAPInsecureSkipVerify,
		StartTLS:             identityProvider.LDAPStartTLS,
		RootCA:               identityProvider.LDAPRootCA,
		BindDN:               identityProvider.LDAPBindDN,
		BindPW:               identityProvider.LDAPBindPW,
		UserSearchBaseDN:     identityProvider.LDAPUserSearchBaseDN,
		UserSearchFilter:     identityProvider.LDAPUserSearchFilter,
		UserSearchUsername:   identityProvider.LDAPUserSearchUsername,
		UserSearchIDAttr:     identityProvider.LDAPUserSearchIDAttr,
		UserSearchEmailAttr:  identityProvider.LDAPUserSearchEmailAttr,
		UserSearchNameAttr:   identityProvider.LDAPUserSearchNameAttr,
		GroupSearchBaseDN:    identityProvider.LDAPGroupSearchBaseDN,
		GroupSearchFilter:    identityProvider.LDAPGroupSearchFilter,
		GroupSearchUserAttr:  identityProvider.LDAPGroupSearchUserAttr,
		GroupSearchGroupAttr: identityProvider.LDAPGroupSearchGroupAttr,
		GroupSearchNameAttr:  identityProvider.LDAPGroupSearchNameAttr,
		RequiredGroups:       identityProvider.GetRequiredGroups(),
	}
}
