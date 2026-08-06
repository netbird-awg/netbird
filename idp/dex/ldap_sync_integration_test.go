package dex

import (
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalLDAPSyncDirectoryIntegration(t *testing.T) {
	if os.Getenv("NB_RUN_LOCAL_LDAP_INTEGRATION_TESTS") != "true" {
		t.Skip("OpenLDAP integration service is not enabled")
	}

	config := &LDAPConnectorConfig{
		Host:                 "openldap:389",
		InsecureNoSSL:        true,
		BindDN:               "cn=admin,dc=example,dc=org",
		BindPW:               os.Getenv("NB_LOCAL_LDAP_TEST_PASSWORD"),
		UserSearchBaseDN:     "ou=users,dc=example,dc=org",
		UserSearchFilter:     "(objectClass=inetOrgPerson)",
		UserSearchUsername:   "uid",
		UserSearchIDAttr:     "uid",
		UserSearchEmailAttr:  "mail",
		UserSearchNameAttr:   "displayName",
		GroupSearchBaseDN:    "ou=groups,dc=example,dc=org",
		GroupSearchFilter:    "(objectClass=groupOfNames)",
		GroupSearchUserAttr:  "DN",
		GroupSearchGroupAttr: "member",
		GroupSearchNameAttr:  "cn",
	}

	diagnostic, err := TestLDAPConnection(t.Context(), config)
	require.NoError(t, err)
	require.Equal(t, "ok", diagnostic.Checks["bind"])
	require.Equal(t, "ok", diagnostic.Checks["group_search"])

	snapshot, err := ReadLDAPDirectory(config, []string{"netbird"}, 5000, 1000)
	require.NoError(t, err)
	require.Len(t, snapshot.Users, 2)
	require.True(t, slices.ContainsFunc(snapshot.Groups, func(group LDAPDirectoryGroup) bool {
		return group.Name == "netbird"
	}))
	for _, user := range snapshot.Users {
		require.Contains(t, user.Groups, "netbird")
		require.NotEmpty(t, user.StableID)
		require.NotEmpty(t, user.Email)
	}
}
