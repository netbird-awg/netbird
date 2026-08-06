package dex

import "fmt"

// LDAPConnectorConfig holds configuration for an LDAP connector
type LDAPConnectorConfig struct {
	Host               string `json:"host"`
	InsecureNoSSL      bool   `json:"insecureNoSSL"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	StartTLS           bool   `json:"startTLS"`
	RootCA             string `json:"rootCA,omitempty"`
	BindDN             string `json:"bindDN"`
	BindPW             string `json:"bindPW"`
	// User search
	UserSearchBaseDN    string `json:"userSearchBaseDN"`
	UserSearchFilter    string `json:"userSearchFilter,omitempty"`
	UserSearchUsername  string `json:"userSearchUsername"`
	UserSearchIDAttr    string `json:"userSearchIDAttr"`
	UserSearchEmailAttr string `json:"userSearchEmailAttr"`
	UserSearchNameAttr  string `json:"userSearchNameAttr"`
	// Group search (optional)
	GroupSearchBaseDN    string `json:"groupSearchBaseDN,omitempty"`
	GroupSearchFilter    string `json:"groupSearchFilter,omitempty"`
	GroupSearchUserAttr  string `json:"groupSearchUserAttr,omitempty"`
	GroupSearchGroupAttr string `json:"groupSearchGroupAttr,omitempty"`
	GroupSearchNameAttr  string `json:"groupSearchNameAttr,omitempty"`
	// RequiredGroups restricts login to users who are members of at least one of these groups.
	RequiredGroups []string `json:"requiredGroups,omitempty"`
}

// buildLDAPConnectorConfig creates config for LDAP connectors
func buildLDAPConnectorConfig(cfg *ConnectorConfig) ([]byte, error) {
	if cfg.LDAP == nil {
		return nil, fmt.Errorf("LDAP configuration is required for LDAP connector")
	}
	l := cfg.LDAP

	ldapConfig := map[string]interface{}{
		"host":               l.Host,
		"insecureNoSSL":      l.InsecureNoSSL,
		"insecureSkipVerify": l.InsecureSkipVerify,
		"startTLS":           l.StartTLS,
		"bindDN":             l.BindDN,
		"bindPW":             l.BindPW,
	}
	if l.RootCA != "" {
		ldapConfig["rootCA"] = l.RootCA
	}

	userSearch := map[string]interface{}{
		"baseDN":    l.UserSearchBaseDN,
		"username":  l.UserSearchUsername,
		"idAttr":    l.UserSearchIDAttr,
		"emailAttr": l.UserSearchEmailAttr,
		"nameAttr":  l.UserSearchNameAttr,
	}
	if l.UserSearchFilter != "" {
		userSearch["filter"] = l.UserSearchFilter
	}
	ldapConfig["userSearch"] = userSearch

	if l.GroupSearchBaseDN != "" {
		groupSearch := map[string]interface{}{
			"baseDN": l.GroupSearchBaseDN,
		}
		if l.GroupSearchFilter != "" {
			groupSearch["filter"] = l.GroupSearchFilter
		}
		if l.GroupSearchNameAttr != "" {
			groupSearch["nameAttr"] = l.GroupSearchNameAttr
		}
		userAttr := l.GroupSearchUserAttr
		if userAttr == "" {
			userAttr = "DN"
		}
		groupAttr := l.GroupSearchGroupAttr
		if groupAttr == "" {
			groupAttr = "member"
		}
		groupSearch["userMatchers"] = []map[string]string{
			{"userAttr": userAttr, "groupAttr": groupAttr},
		}
		ldapConfig["groupSearch"] = groupSearch
	}

	if len(l.RequiredGroups) > 0 {
		ldapConfig["requiredGroups"] = l.RequiredGroups
	}
	addNetBirdConnectorMetadata(ldapConfig, cfg)

	return encodeConnectorConfig(ldapConfig)
}

// parseLDAPConfigMap extracts LDAPConnectorConfig from a raw config map
func parseLDAPConfigMap(m map[string]interface{}) *LDAPConnectorConfig {
	l := &LDAPConnectorConfig{}
	if v, ok := m["host"].(string); ok {
		l.Host = v
	}
	if v, ok := m["insecureNoSSL"].(bool); ok {
		l.InsecureNoSSL = v
	}
	if v, ok := m["insecureSkipVerify"].(bool); ok {
		l.InsecureSkipVerify = v
	}
	if v, ok := m["startTLS"].(bool); ok {
		l.StartTLS = v
	}
	if v, ok := m["rootCA"].(string); ok {
		l.RootCA = v
	}
	if v, ok := m["bindDN"].(string); ok {
		l.BindDN = v
	}
	if v, ok := m["bindPW"].(string); ok {
		l.BindPW = v
	}
	if us, ok := m["userSearch"].(map[string]interface{}); ok {
		if v, ok := us["baseDN"].(string); ok {
			l.UserSearchBaseDN = v
		}
		if v, ok := us["filter"].(string); ok {
			l.UserSearchFilter = v
		}
		if v, ok := us["username"].(string); ok {
			l.UserSearchUsername = v
		}
		if v, ok := us["idAttr"].(string); ok {
			l.UserSearchIDAttr = v
		}
		if v, ok := us["emailAttr"].(string); ok {
			l.UserSearchEmailAttr = v
		}
		if v, ok := us["nameAttr"].(string); ok {
			l.UserSearchNameAttr = v
		}
	}
	if gs, ok := m["groupSearch"].(map[string]interface{}); ok {
		if v, ok := gs["baseDN"].(string); ok {
			l.GroupSearchBaseDN = v
		}
		if v, ok := gs["filter"].(string); ok {
			l.GroupSearchFilter = v
		}
		if v, ok := gs["nameAttr"].(string); ok {
			l.GroupSearchNameAttr = v
		}
		if matchers, ok := gs["userMatchers"].([]interface{}); ok && len(matchers) > 0 {
			if m0, ok := matchers[0].(map[string]interface{}); ok {
				if v, ok := m0["userAttr"].(string); ok {
					l.GroupSearchUserAttr = v
				}
				if v, ok := m0["groupAttr"].(string); ok {
					l.GroupSearchGroupAttr = v
				}
			}
		}
	}
	if rg, ok := m["requiredGroups"].([]interface{}); ok {
		for _, g := range rg {
			if s, ok := g.(string); ok {
				l.RequiredGroups = append(l.RequiredGroups, s)
			}
		}
	}
	return l
}
