package types

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm/schema"
)

func TestIdentityProviderLDAPEmbeddingPreservesDatabaseColumns(t *testing.T) {
	parsed, err := schema.Parse(&IdentityProvider{}, &sync.Map{}, schema.NamingStrategy{})
	require.NoError(t, err)

	for fieldName, columnName := range map[string]string{
		"LDAPHost":           "ldap_host",
		"LDAPBindDN":         "ldap_bind_dn",
		"LDAPBindPW":         "ldap_bind_pw",
		"LDAPRequiredGroups": "ldap_required_groups",
	} {
		field := parsed.LookUpField(fieldName)
		require.NotNil(t, field, fieldName)
		assert.Equal(t, columnName, field.DBName)
	}
}

func TestIdentityProviderCopyIncludesLDAPConfiguration(t *testing.T) {
	original := &IdentityProvider{
		ID: "ldap-idp",
		IdentityProviderLDAP: IdentityProviderLDAP{
			LDAPHost:           "ldap.example.com:636",
			LDAPBindDN:         "cn=admin,dc=example,dc=com",
			LDAPRequiredGroups: "developers,operators",
		},
	}

	identityProviderCopy := original.Copy()
	assert.Equal(t, original.IdentityProviderLDAP, identityProviderCopy.IdentityProviderLDAP)
	assert.Equal(t, []string{"developers", "operators"}, identityProviderCopy.GetRequiredGroups())
}
