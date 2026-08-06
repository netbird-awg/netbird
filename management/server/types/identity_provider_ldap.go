package types

import (
	"errors"
	"strings"
)

var (
	ErrIdentityProviderLDAPHostRequired             = errors.New("LDAP host is required")
	ErrIdentityProviderLDAPBindDNRequired           = errors.New("LDAP bind DN is required")
	ErrIdentityProviderLDAPUserSearchBaseDNRequired = errors.New("LDAP user search base DN is required")
)

// IdentityProviderLDAP contains the local LDAP extension fields. It is embedded
// in IdentityProvider so GORM keeps the existing flat ldap_* column layout.
type IdentityProviderLDAP struct {
	LDAPHost                 string `gorm:"column:ldap_host"`
	LDAPInsecureNoSSL        bool   `gorm:"column:ldap_insecure_no_ssl"`
	LDAPInsecureSkipVerify   bool   `gorm:"column:ldap_insecure_skip_verify"`
	LDAPStartTLS             bool   `gorm:"column:ldap_start_tls"`
	LDAPRootCA               string `gorm:"column:ldap_root_ca"`
	LDAPBindDN               string `gorm:"column:ldap_bind_dn"`
	LDAPBindPW               string `gorm:"column:ldap_bind_pw"`
	LDAPUserSearchBaseDN     string `gorm:"column:ldap_user_search_base_dn"`
	LDAPUserSearchFilter     string `gorm:"column:ldap_user_search_filter"`
	LDAPUserSearchUsername   string `gorm:"column:ldap_user_search_username"`
	LDAPUserSearchIDAttr     string `gorm:"column:ldap_user_search_id_attr"`
	LDAPUserSearchEmailAttr  string `gorm:"column:ldap_user_search_email_attr"`
	LDAPUserSearchNameAttr   string `gorm:"column:ldap_user_search_name_attr"`
	LDAPGroupSearchBaseDN    string `gorm:"column:ldap_group_search_base_dn"`
	LDAPGroupSearchFilter    string `gorm:"column:ldap_group_search_filter"`
	LDAPGroupSearchUserAttr  string `gorm:"column:ldap_group_search_user_attr"`
	LDAPGroupSearchGroupAttr string `gorm:"column:ldap_group_search_group_attr"`
	LDAPGroupSearchNameAttr  string `gorm:"column:ldap_group_search_name_attr"`
	LDAPRequiredGroups       string `gorm:"column:ldap_required_groups"`
}

func (idp *IdentityProvider) GetRequiredGroups() []string {
	if idp.LDAPRequiredGroups == "" {
		return nil
	}
	return strings.Split(idp.LDAPRequiredGroups, ",")
}

func (idp *IdentityProvider) SetRequiredGroups(groups []string) {
	idp.LDAPRequiredGroups = strings.Join(groups, ",")
}

func (idp *IdentityProvider) validateLDAP() error {
	if idp.LDAPHost == "" {
		return ErrIdentityProviderLDAPHostRequired
	}
	if idp.LDAPBindDN == "" {
		return ErrIdentityProviderLDAPBindDNRequired
	}
	if idp.LDAPUserSearchBaseDN == "" {
		return ErrIdentityProviderLDAPUserSearchBaseDNRequired
	}
	return nil
}
