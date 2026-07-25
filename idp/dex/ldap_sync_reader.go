package dex

import (
	"fmt"
	"slices"
	"strings"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

// LDAPDirectoryUser is the sanitized directory representation consumed by
// local synchronization. It never contains passwords or arbitrary attributes.
type LDAPDirectoryUser struct {
	StableID string
	Email    string
	Name     string
	DN       string
	Groups   []string
}

// LDAPDirectoryGroup represents a source LDAP group.
type LDAPDirectoryGroup struct {
	StableID string
	Name     string
}

// LDAPDirectorySnapshot is a bounded point-in-time view used by both preview
// and run so their filtering semantics stay identical.
type LDAPDirectorySnapshot struct {
	Users  []LDAPDirectoryUser
	Groups []LDAPDirectoryGroup
}

// ReadLDAPDirectory reads users and groups using the Connector search
// configuration. scopeGroups is a synchronization scope and is deliberately
// separate from RequiredGroups, which remains a login restriction.
func ReadLDAPDirectory(cfg *LDAPConnectorConfig, scopeGroups []string, maxUsers, maxGroups int) (*LDAPDirectorySnapshot, error) {
	if cfg == nil {
		return nil, fmt.Errorf("LDAP connector config is nil")
	}
	if maxUsers <= 0 || maxGroups <= 0 {
		return nil, fmt.Errorf("LDAP directory limits must be positive")
	}

	attrs := []string{
		cfg.UserSearchIDAttr,
		cfg.UserSearchEmailAttr,
		cfg.UserSearchNameAttr,
		cfg.UserSearchUsername,
	}
	for _, attr := range attrs {
		if strings.TrimSpace(attr) == "" || !isValidLDAPAttributeName(attr) {
			return nil, fmt.Errorf("invalid LDAP user attribute %q", attr)
		}
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to LDAP: %w", err)
	}
	defer conn.Close()
	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return nil, fmt.Errorf("bind to LDAP: %w", err)
	}

	users, membershipValues, err := readLDAPUsers(conn, cfg, maxUsers)
	if err != nil {
		return nil, err
	}
	groups, memberships, err := readLDAPGroups(conn, cfg, maxGroups)
	if err != nil {
		return nil, err
	}

	scope := make(map[string]struct{}, len(scopeGroups))
	for _, group := range scopeGroups {
		group = strings.ToLower(strings.TrimSpace(group))
		if group != "" {
			scope[group] = struct{}{}
		}
	}

	filtered := make([]LDAPDirectoryUser, 0, len(users))
	for index := range users {
		for groupName, members := range memberships {
			if _, ok := members[strings.ToLower(membershipValues[index])]; ok {
				users[index].Groups = append(users[index].Groups, groupName)
			}
		}
		slices.Sort(users[index].Groups)
		if len(scope) == 0 || containsScopedLDAPGroup(users[index].Groups, scope) {
			filtered = append(filtered, users[index])
		}
	}

	return &LDAPDirectorySnapshot{Users: filtered, Groups: groups}, nil
}

func readLDAPUsers(conn *ldapv3.Conn, cfg *LDAPConnectorConfig, limit int) ([]LDAPDirectoryUser, []string, error) {
	filter, err := normalizedLDAPFilter(cfg.UserSearchFilter)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid LDAP user filter: %w", err)
	}
	userAttr := strings.TrimSpace(cfg.GroupSearchUserAttr)
	if userAttr == "" {
		userAttr = "DN"
	}
	if !strings.EqualFold(userAttr, "DN") && !isValidLDAPAttributeName(userAttr) {
		return nil, nil, fmt.Errorf("invalid LDAP group user attribute %q", userAttr)
	}
	attributes := uniqueLDAPAttributes([]string{
		cfg.UserSearchIDAttr,
		cfg.UserSearchEmailAttr,
		cfg.UserSearchNameAttr,
		cfg.UserSearchUsername,
		userAttr,
	})
	result, err := conn.Search(ldapv3.NewSearchRequest(
		cfg.UserSearchBaseDN,
		ldapv3.ScopeWholeSubtree,
		ldapv3.NeverDerefAliases,
		limit+1,
		15,
		false,
		filter,
		attributes,
		nil,
	))
	if err != nil {
		return nil, nil, fmt.Errorf("search LDAP users: %w", err)
	}
	if len(result.Entries) > limit {
		return nil, nil, fmt.Errorf("LDAP user limit exceeded: maximum %d", limit)
	}

	users := make([]LDAPDirectoryUser, 0, len(result.Entries))
	membershipValues := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		stableID := strings.TrimSpace(entry.GetAttributeValue(cfg.UserSearchIDAttr))
		email := strings.ToLower(strings.TrimSpace(entry.GetAttributeValue(cfg.UserSearchEmailAttr)))
		name := strings.TrimSpace(entry.GetAttributeValue(cfg.UserSearchNameAttr))
		if name == "" {
			name = email
		}
		membershipValue := entry.DN
		if !strings.EqualFold(userAttr, "DN") {
			membershipValue = entry.GetAttributeValue(userAttr)
		}
		users = append(users, LDAPDirectoryUser{StableID: stableID, Email: email, Name: name, DN: entry.DN})
		membershipValues = append(membershipValues, membershipValue)
	}
	return users, membershipValues, nil
}

func readLDAPGroups(conn *ldapv3.Conn, cfg *LDAPConnectorConfig, limit int) ([]LDAPDirectoryGroup, map[string]map[string]struct{}, error) {
	if strings.TrimSpace(cfg.GroupSearchBaseDN) == "" {
		return nil, map[string]map[string]struct{}{}, nil
	}
	filter, err := normalizedLDAPFilter(cfg.GroupSearchFilter)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid LDAP group filter: %w", err)
	}
	groupAttr, err := configuredLDAPGroupAttribute(cfg)
	if err != nil {
		return nil, nil, err
	}
	nameAttr := strings.TrimSpace(cfg.GroupSearchNameAttr)
	if nameAttr == "" {
		nameAttr = "cn"
	}
	if !isValidLDAPAttributeName(nameAttr) {
		return nil, nil, fmt.Errorf("invalid LDAP group name attribute %q", nameAttr)
	}
	result, err := conn.Search(ldapv3.NewSearchRequest(
		cfg.GroupSearchBaseDN,
		ldapv3.ScopeWholeSubtree,
		ldapv3.NeverDerefAliases,
		limit+1,
		15,
		false,
		filter,
		[]string{nameAttr, groupAttr, "entryUUID", "objectGUID"},
		nil,
	))
	if err != nil {
		return nil, nil, fmt.Errorf("search LDAP groups: %w", err)
	}
	if len(result.Entries) > limit {
		return nil, nil, fmt.Errorf("LDAP group limit exceeded: maximum %d", limit)
	}

	groups := make([]LDAPDirectoryGroup, 0, len(result.Entries))
	memberships := make(map[string]map[string]struct{}, len(result.Entries))
	seenNames := make(map[string]struct{}, len(result.Entries))
	for _, entry := range result.Entries {
		name := strings.TrimSpace(entry.GetAttributeValue(nameAttr))
		if name == "" {
			continue
		}
		nameKey := strings.ToLower(name)
		if _, duplicate := seenNames[nameKey]; duplicate {
			return nil, nil, fmt.Errorf("duplicate LDAP group name %q", name)
		}
		seenNames[nameKey] = struct{}{}
		stableID := strings.TrimSpace(entry.GetAttributeValue("entryUUID"))
		if stableID == "" {
			stableID = strings.TrimSpace(entry.GetAttributeValue("objectGUID"))
		}
		if stableID == "" {
			stableID = strings.ToLower(entry.DN)
		}
		groups = append(groups, LDAPDirectoryGroup{StableID: stableID, Name: name})
		members := make(map[string]struct{})
		for _, member := range entry.GetAttributeValues(groupAttr) {
			members[strings.ToLower(strings.TrimSpace(member))] = struct{}{}
		}
		memberships[name] = members
	}
	return groups, memberships, nil
}

func normalizedLDAPFilter(raw string) (string, error) {
	filter := strings.TrimSpace(raw)
	if filter == "" {
		filter = "(objectClass=*)"
	}
	if _, err := ldapv3.CompileFilter(filter); err != nil {
		return "", err
	}
	return filter, nil
}

func uniqueLDAPAttributes(attributes []string) []string {
	seen := make(map[string]struct{}, len(attributes))
	result := make([]string, 0, len(attributes))
	for _, attr := range attributes {
		attr = strings.TrimSpace(attr)
		if attr == "" || strings.EqualFold(attr, "DN") {
			continue
		}
		key := strings.ToLower(attr)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, attr)
	}
	return result
}

func containsScopedLDAPGroup(groups []string, scope map[string]struct{}) bool {
	for _, group := range groups {
		if _, ok := scope[strings.ToLower(group)]; ok {
			return true
		}
	}
	return false
}
