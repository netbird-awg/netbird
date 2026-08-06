package idp

import (
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func applyLDAPAPIResponse(response *api.IdentityProvider, identityProvider *types.IdentityProvider) {
	if identityProvider.Type != types.IdentityProviderTypeLDAP {
		return
	}
	response.Ldap = &api.IdentityProviderLDAP{
		Host:                 identityProvider.LDAPHost,
		InsecureNoSSL:        identityProvider.LDAPInsecureNoSSL,
		InsecureSkipVerify:   identityProvider.LDAPInsecureSkipVerify,
		StartTLS:             identityProvider.LDAPStartTLS,
		RootCA:               identityProvider.LDAPRootCA,
		BindDN:               identityProvider.LDAPBindDN,
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

func applyLDAPAPIRequest(identityProvider *types.IdentityProvider, ldap *api.IdentityProviderLDAP) {
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
