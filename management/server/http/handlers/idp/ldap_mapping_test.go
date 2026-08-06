package idp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

func TestIdentityProviderAPIResponseNeverContainsConnectorSecrets(t *testing.T) {
	response := toAPIResponse(&types.IdentityProvider{
		ID:           "ldap-a",
		Type:         types.IdentityProviderTypeLDAP,
		Name:         "OpenLDAP",
		ClientSecret: "oidc-secret-must-not-leak",
		IdentityProviderLDAP: types.IdentityProviderLDAP{
			LDAPHost:   "ldap.example.org:636",
			LDAPBindDN: "cn=admin,dc=example,dc=org",
			LDAPBindPW: "ldap-secret-must-not-leak",
		},
	})

	require.True(t, response.SecretConfigured)
	require.NotNil(t, response.Ldap)
	require.Empty(t, response.Ldap.BindPW)

	payload, err := json.Marshal(response)
	require.NoError(t, err)
	require.NotContains(t, string(payload), "oidc-secret-must-not-leak")
	require.NotContains(t, string(payload), "ldap-secret-must-not-leak")
}
