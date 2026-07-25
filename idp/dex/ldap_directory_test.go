package dex

import (
	"fmt"
	"os"
	"strings"
	"testing"

	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLDAPGroupAddRequestUsesConfiguredSchema(t *testing.T) {
	testCases := []struct {
		name            string
		groupAttr       string
		membershipValue string
		objectClass     string
		expectGID       bool
	}{
		{name: "group of names", groupAttr: "member", membershipValue: "uid=user,ou=users,dc=example,dc=org", objectClass: "groupOfNames"},
		{name: "group of unique names", groupAttr: "uniqueMember", membershipValue: "uid=user,ou=users,dc=example,dc=org", objectClass: "groupOfUniqueNames"},
		{name: "posix group", groupAttr: "memberUid", membershipValue: "user", objectClass: "posixGroup", expectGID: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			request, err := newLDAPGroupAddRequest(
				"cn=netbird,ou=groups,dc=example,dc=org",
				"netbird",
				testCase.groupAttr,
				testCase.membershipValue,
			)
			require.NoError(t, err)

			assert.Equal(t, []string{testCase.objectClass}, addRequestAttributeValues(request, "objectClass"))
			assert.Equal(t, []string{testCase.membershipValue}, addRequestAttributeValues(request, testCase.groupAttr))
			if testCase.expectGID {
				assert.NotEmpty(t, addRequestAttributeValues(request, "gidNumber"))
			} else {
				assert.Empty(t, addRequestAttributeValues(request, "gidNumber"))
			}
		})
	}
}

func TestNewLDAPGroupAddRequestUsesValidEmptyGroupPlaceholder(t *testing.T) {
	groupDN := "cn=netbird,ou=groups,dc=example,dc=org"
	request, err := newLDAPGroupAddRequest(groupDN, "netbird", "member", "")
	require.NoError(t, err)

	assert.Equal(t, []string{"cn=__netbird_empty__," + groupDN}, addRequestAttributeValues(request, "member"))
}

func TestLDAPGroupMembershipValueUsesConfiguredUserAttribute(t *testing.T) {
	cfg := &LDAPConnectorConfig{GroupSearchUserAttr: "DN"}
	value, err := ldapGroupMembershipValue(nil, cfg, "uid=user,ou=users,dc=example,dc=org")
	require.NoError(t, err)
	assert.Equal(t, "uid=user,ou=users,dc=example,dc=org", value)
}

func TestConfiguredLDAPGroupAttributeRejectsFilterInjection(t *testing.T) {
	_, err := configuredLDAPGroupAttribute(&LDAPConnectorConfig{GroupSearchGroupAttr: "member)(objectClass=*"})
	require.Error(t, err)
}

func TestOpenLDAPUserProvisioningRejectsUnsupportedSchema(t *testing.T) {
	err := validateOpenLDAPUserProvisioningConfig(&LDAPConnectorConfig{
		UserSearchUsername:  "sAMAccountName",
		UserSearchIDAttr:    "objectGUID",
		UserSearchEmailAttr: "mail",
		UserSearchNameAttr:  "displayName",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires username attribute")
}

func TestLDAPGroupCreationRejectsNonCNNameAttribute(t *testing.T) {
	err := validateLDAPGroupCreationConfig(&LDAPConnectorConfig{GroupSearchNameAttr: "displayName"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be created in the directory first")
}

func TestHasOtherLDAPGroupMember(t *testing.T) {
	assert.False(t, hasOtherLDAPGroupMember([]string{"uid=user"}, "uid=user"))
	assert.True(t, hasOtherLDAPGroupMember([]string{"uid=user", "uid=other"}, "uid=user"))
}

func TestLDAPDirectoryIntegration(t *testing.T) {
	host := os.Getenv("NETBIRD_LDAP_TEST_HOST")
	if host == "" {
		t.Skip("NETBIRD_LDAP_TEST_HOST is not set")
	}
	bindPassword := os.Getenv("NB_LOCAL_LDAP_TEST_PASSWORD")
	if bindPassword == "" {
		bindPassword = "adminpassword"
	}

	baseDN := "dc=example,dc=org"
	testCases := []struct {
		name      string
		groupAttr string
		userAttr  string
	}{
		{name: "member", groupAttr: "member", userAttr: "DN"},
		{name: "unique-member", groupAttr: "uniqueMember", userAttr: "DN"},
		{name: "member-uid", groupAttr: "memberUid", userAttr: "uid"},
	}

	for index, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			email := fmt.Sprintf("schema-user-%d@example.org", index)
			groupName := "netbird-" + testCase.name
			cfg := &LDAPConnectorConfig{
				Host:                 host,
				InsecureNoSSL:        true,
				BindDN:               "cn=admin," + baseDN,
				BindPW:               bindPassword,
				UserSearchBaseDN:     "ou=users," + baseDN,
				UserSearchUsername:   "uid",
				UserSearchIDAttr:     "entryUUID",
				UserSearchEmailAttr:  "mail",
				UserSearchNameAttr:   "cn",
				GroupSearchBaseDN:    "ou=groups," + baseDN,
				GroupSearchNameAttr:  "cn",
				GroupSearchGroupAttr: testCase.groupAttr,
				GroupSearchUserAttr:  testCase.userAttr,
				RequiredGroups:       []string{groupName},
			}

			require.NoError(t, CreateLDAPUser(cfg, email, "SchemaPass@123", "Schema User"))
			t.Cleanup(func() { _ = DeleteLDAPUser(cfg, email) })
			require.NoError(t, AddUserToLDAPGroups(cfg, email, []string{groupName}))

			member, err := CheckUserInLDAPGroups(cfg, email)
			require.NoError(t, err)
			assert.True(t, member)

			groups, err := ListLDAPGroups(cfg)
			require.NoError(t, err)
			assert.Contains(t, groups, groupName)

			ldapUser, err := FindLDAPUserByEmail(cfg, email)
			require.NoError(t, err)
			membershipValue := ldapUser.DN
			if strings.EqualFold(testCase.userAttr, "uid") {
				membershipValue, err = ldapUIDFromEmail(email)
				require.NoError(t, err)
			}
			require.NoError(t, DeleteLDAPDirectoryUser(cfg, ldapUser.StableID))
			assertLDAPGroupHasNoUserMembership(t, cfg, membershipValue, groupName)
			require.NoError(t, DeleteLDAPUser(cfg, email), "LDAP deletion should be idempotent for safe retries")
		})
	}
}

func TestLDAPDirectoryIntegration_GroupLookupUsesConfiguredSubtree(t *testing.T) {
	host := os.Getenv("NETBIRD_LDAP_TEST_HOST")
	if host == "" {
		t.Skip("NETBIRD_LDAP_TEST_HOST is not set")
	}
	bindPassword := os.Getenv("NB_LOCAL_LDAP_TEST_PASSWORD")
	if bindPassword == "" {
		bindPassword = "adminpassword"
	}

	baseDN := "dc=example,dc=org"
	groupBaseDN := "ou=groups," + baseDN
	nestedBaseDN := "ou=nested," + groupBaseDN
	groupName := "netbird-nested"
	groupDN := ldapGroupDN(groupName, nestedBaseDN)
	email := "nested-user@example.org"
	cfg := &LDAPConnectorConfig{
		Host:                 host,
		InsecureNoSSL:        true,
		BindDN:               "cn=admin," + baseDN,
		BindPW:               bindPassword,
		UserSearchBaseDN:     "ou=users," + baseDN,
		UserSearchUsername:   "uid",
		UserSearchIDAttr:     "entryUUID",
		UserSearchEmailAttr:  "mail",
		UserSearchNameAttr:   "cn",
		GroupSearchBaseDN:    groupBaseDN,
		GroupSearchFilter:    "(objectClass=groupOfNames)",
		GroupSearchNameAttr:  "cn",
		GroupSearchGroupAttr: "member",
		GroupSearchUserAttr:  "DN",
		RequiredGroups:       []string{groupName},
	}

	conn, err := dialLDAP(cfg)
	require.NoError(t, err)
	require.NoError(t, conn.Bind(cfg.BindDN, cfg.BindPW))
	ou := ldapv3.NewAddRequest(nestedBaseDN, nil)
	ou.Attribute("objectClass", []string{"organizationalUnit"})
	ou.Attribute("ou", []string{"nested"})
	if err := conn.Add(ou); err != nil && !ldapv3.IsErrorWithCode(err, ldapv3.LDAPResultEntryAlreadyExists) {
		require.NoError(t, err)
	}
	group, err := newLDAPGroupAddRequest(groupDN, groupName, "member", "")
	require.NoError(t, err)
	if err := conn.Add(group); err != nil && !ldapv3.IsErrorWithCode(err, ldapv3.LDAPResultEntryAlreadyExists) {
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		_ = conn.Del(ldapv3.NewDelRequest(groupDN, nil))
		_ = conn.Del(ldapv3.NewDelRequest(nestedBaseDN, nil))
		_ = conn.Close()
	})

	require.NoError(t, CreateLDAPUser(cfg, email, "NestedPass1!", "Nested User"))
	t.Cleanup(func() { _ = DeleteLDAPUser(cfg, email) })
	require.NoError(t, AddUserToLDAPGroups(cfg, email, []string{groupName}))
	member, err := CheckUserInLDAPGroups(cfg, email)
	require.NoError(t, err)
	require.True(t, member)

	_, err = conn.Search(ldapv3.NewSearchRequest(
		ldapGroupDN(groupName, groupBaseDN),
		ldapv3.ScopeBaseObject,
		ldapv3.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"cn"},
		nil,
	))
	require.True(t, ldapv3.IsErrorWithCode(err, ldapv3.LDAPResultNoSuchObject), "must not create a duplicate group at the search base")
}

func TestDeleteLDAPDirectoryUserRejectsMissingConfig(t *testing.T) {
	err := DeleteLDAPDirectoryUser(nil, "user@example.org")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LDAP connector config is nil")
}

func assertLDAPGroupHasNoUserMembership(t *testing.T, cfg *LDAPConnectorConfig, membershipValue, groupName string) {
	t.Helper()
	conn, err := dialLDAP(cfg)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.Bind(cfg.BindDN, cfg.BindPW))

	groupAttr, err := configuredLDAPGroupAttribute(cfg)
	require.NoError(t, err)
	groupDN := ldapGroupDN(groupName, cfg.GroupSearchBaseDN)

	result, err := conn.Search(ldapv3.NewSearchRequest(
		groupDN,
		ldapv3.ScopeBaseObject, ldapv3.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{groupAttr},
		nil,
	))
	require.NoError(t, err)
	require.Len(t, result.Entries, 1)
	assert.NotContains(t, result.Entries[0].GetAttributeValues(groupAttr), membershipValue)
}

func addRequestAttributeValues(request *ldapv3.AddRequest, name string) []string {
	for _, attribute := range request.Attributes {
		if attribute.Type == name {
			return attribute.Vals
		}
	}
	return nil
}
