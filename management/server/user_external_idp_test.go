package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

func TestDeleteLDAPDirectoryUserSkipsNonLDAPSubjects(t *testing.T) {
	testCases := []struct {
		name       string
		manager    *DefaultAccountManager
		targetUser *types.UserInfo
	}{
		{
			name:       "no embedded identity provider",
			manager:    &DefaultAccountManager{},
			targetUser: &types.UserInfo{ID: dex.EncodeDexUserID("user", "ldap")},
		},
		{
			name:       "nil user",
			manager:    &DefaultAccountManager{idpManager: &idp.EmbeddedIdPManager{}},
			targetUser: nil,
		},
		{
			name:       "malformed subject",
			manager:    &DefaultAccountManager{idpManager: &idp.EmbeddedIdPManager{}},
			targetUser: &types.UserInfo{ID: "not-a-dex-subject"},
		},
		{
			name:       "local password subject",
			manager:    &DefaultAccountManager{idpManager: &idp.EmbeddedIdPManager{}},
			targetUser: &types.UserInfo{ID: dex.EncodeDexUserID("user", "local")},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			deleted, err := testCase.manager.deleteLDAPDirectoryUser(context.Background(), "account", testCase.targetUser)
			require.NoError(t, err)
			require.False(t, deleted)
		})
	}
}

func TestLDAPGroupRestrictionAppliesToExistingUsersFromTokenClaims(t *testing.T) {
	manager, _, err := createManagerWithEmbeddedIdP(t)
	require.NoError(t, err)
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: "owner"})
	require.NoError(t, err)
	provider, err := manager.CreateIdentityProvider(context.Background(), account.Id, "owner", &types.IdentityProvider{
		Name: "Restricted LDAP",
		Type: types.IdentityProviderTypeLDAP,
		IdentityProviderLDAP: types.IdentityProviderLDAP{
			LDAPHost:                "ldap.example.com:636",
			LDAPBindDN:              "cn=admin,dc=example,dc=com",
			LDAPBindPW:              "secret",
			LDAPUserSearchBaseDN:    "ou=people,dc=example,dc=com",
			LDAPUserSearchUsername:  "uid",
			LDAPUserSearchIDAttr:    "entryUUID",
			LDAPUserSearchEmailAttr: "mail",
			LDAPUserSearchNameAttr:  "cn",
			LDAPRequiredGroups:      "netbird",
		},
	})
	require.NoError(t, err)

	userAuth := auth.UserAuth{
		UserId: dex.EncodeDexUserID("stable-user", provider.ID),
		Groups: []string{"NetBird"},
	}
	require.NoError(t, manager.checkLDAPGroupRestriction(context.Background(), account.Id, userAuth))

	userAuth.Groups = []string{"other"}
	require.Error(t, manager.checkLDAPGroupRestriction(context.Background(), account.Id, userAuth))
}
