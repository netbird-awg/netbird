package types

import "strings"

const DefaultLDAPUserGroup = "netbird"

// NormalizeLDAPUserGroups guarantees the mandatory default LDAP group while
// trimming empty values and removing case-insensitive duplicates.
func NormalizeLDAPUserGroups(groups []string) []string {
	result := make([]string, 0, len(groups)+1)
	seen := make(map[string]struct{}, len(groups)+1)

	appendGroup := func(group string) {
		group = strings.TrimSpace(group)
		if group == "" {
			return
		}
		key := strings.ToLower(group)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		result = append(result, group)
	}

	appendGroup(DefaultLDAPUserGroup)
	for _, group := range groups {
		appendGroup(group)
	}
	return result
}
