package dex

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

var (
	ErrLDAPUserNotFound  = errors.New("LDAP user not found")
	ErrLDAPGroupNotFound = errors.New("LDAP group not found")
)

// CreateLDAPUser creates a new user entry in the LDAP directory using the connector's bind credentials.
// It derives uid from email (local part), and creates an inetOrgPerson with posixAccount attributes.
func CreateLDAPUser(cfg *LDAPConnectorConfig, email, password, fullName string) error {
	if cfg == nil {
		return fmt.Errorf("LDAP connector config is nil")
	}
	if email == "" || password == "" || fullName == "" {
		return fmt.Errorf("email, password and name are required")
	}
	if err := validateOpenLDAPUserProvisioningConfig(cfg); err != nil {
		return err
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	uid, err := ldapUIDFromEmail(email)
	if err != nil {
		return err
	}

	nameParts := strings.Fields(fullName)
	sn := nameParts[len(nameParts)-1]
	givenName := fullName
	if len(nameParts) > 1 {
		givenName = strings.Join(nameParts[:len(nameParts)-1], " ")
	}

	dn := ldapUserDN(uid, cfg.UserSearchBaseDN)

	addReq := ldapv3.NewAddRequest(dn, nil)
	addReq.Attribute("objectClass", []string{"inetOrgPerson", "posixAccount", "shadowAccount"})
	addReq.Attribute("uid", []string{uid})
	addReq.Attribute("cn", []string{fullName})
	addReq.Attribute("sn", []string{sn})
	addReq.Attribute("givenName", []string{givenName})
	addReq.Attribute("mail", []string{email})
	addReq.Attribute("userPassword", []string{password})
	addReq.Attribute("uidNumber", []string{fmt.Sprintf("%d", generateUIDNumber(uid))})
	addReq.Attribute("gidNumber", []string{"500"})
	addReq.Attribute("homeDirectory", []string{fmt.Sprintf("/home/%s", uid)})
	addReq.Attribute("loginShell", []string{"/bin/bash"})

	if err := conn.Add(addReq); err != nil {
		return fmt.Errorf("failed to create LDAP user %q: %w", uid, err)
	}

	return nil
}

// DeleteLDAPUser removes a user entry from the LDAP directory.
func DeleteLDAPUser(cfg *LDAPConnectorConfig, email string) error {
	if cfg == nil {
		return fmt.Errorf("LDAP connector config is nil")
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	user, err := findLDAPUser(conn, cfg, cfg.UserSearchEmailAttr, email)
	if errors.Is(err, ErrLDAPUserNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	if err := conn.Del(ldapv3.NewDelRequest(user.DN, nil)); err != nil && !ldapv3.IsErrorWithCode(err, ldapv3.LDAPResultNoSuchObject) {
		return fmt.Errorf("failed to delete LDAP user %q: %w", user.StableID, err)
	}
	return nil
}

// DeleteLDAPDirectoryUser removes all known group references before deleting
// the directory entry. Deleting a missing directory entry is treated as a
// success so the NetBird deletion flow can be retried safely.
func DeleteLDAPDirectoryUser(cfg *LDAPConnectorConfig, stableID string) error {
	if cfg == nil {
		return fmt.Errorf("LDAP connector config is nil")
	}
	conn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()
	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind to LDAP: %w", err)
	}
	user, err := findLDAPUser(conn, cfg, cfg.UserSearchIDAttr, stableID)
	if errors.Is(err, ErrLDAPUserNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := removeLDAPUserFromGroups(conn, cfg, user); err != nil {
		return fmt.Errorf("failed to remove LDAP group memberships: %w", err)
	}
	if err := conn.Del(ldapv3.NewDelRequest(user.DN, nil)); err != nil && !ldapv3.IsErrorWithCode(err, ldapv3.LDAPResultNoSuchObject) {
		return fmt.Errorf("failed to delete LDAP user %q: %w", stableID, err)
	}
	return nil
}

// FindLDAPUserByEmail resolves the stable connector identity and exact LDAP DN.
func FindLDAPUserByEmail(cfg *LDAPConnectorConfig, email string) (*LDAPDirectoryUser, error) {
	return findLDAPUserWithAdminBind(cfg, cfg.UserSearchEmailAttr, email)
}

func findLDAPUserWithAdminBind(cfg *LDAPConnectorConfig, attribute, value string) (*LDAPDirectoryUser, error) {
	if cfg == nil {
		return nil, fmt.Errorf("LDAP connector config is nil")
	}
	conn, err := dialLDAP(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()
	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return nil, fmt.Errorf("failed to bind to LDAP: %w", err)
	}
	return findLDAPUser(conn, cfg, attribute, value)
}

func findLDAPUser(conn *ldapv3.Conn, cfg *LDAPConnectorConfig, attribute, value string) (*LDAPDirectoryUser, error) {
	attribute = strings.TrimSpace(attribute)
	value = strings.TrimSpace(value)
	if !isValidLDAPAttributeName(attribute) || value == "" {
		return nil, fmt.Errorf("invalid LDAP user lookup")
	}
	baseFilter, err := normalizedLDAPFilter(cfg.UserSearchFilter)
	if err != nil {
		return nil, fmt.Errorf("invalid LDAP user filter: %w", err)
	}
	filter := fmt.Sprintf("(&%s(%s=%s))", baseFilter, attribute, ldapv3.EscapeFilter(value))
	result, err := conn.Search(ldapv3.NewSearchRequest(
		cfg.UserSearchBaseDN,
		ldapv3.ScopeWholeSubtree,
		ldapv3.NeverDerefAliases,
		2,
		15,
		false,
		filter,
		uniqueLDAPAttributes([]string{cfg.UserSearchIDAttr, cfg.UserSearchEmailAttr, cfg.UserSearchNameAttr}),
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP user: %w", err)
	}
	if len(result.Entries) == 0 {
		return nil, ErrLDAPUserNotFound
	}
	if len(result.Entries) != 1 {
		return nil, fmt.Errorf("LDAP user lookup is ambiguous")
	}
	entry := result.Entries[0]
	stableID := strings.TrimSpace(entry.GetAttributeValue(cfg.UserSearchIDAttr))
	if stableID == "" {
		return nil, fmt.Errorf("LDAP user has no configured stable ID attribute %q", cfg.UserSearchIDAttr)
	}
	return &LDAPDirectoryUser{
		StableID: stableID,
		Email:    strings.ToLower(strings.TrimSpace(entry.GetAttributeValue(cfg.UserSearchEmailAttr))),
		Name:     strings.TrimSpace(entry.GetAttributeValue(cfg.UserSearchNameAttr)),
		DN:       entry.DN,
	}, nil
}

func dialLDAP(cfg *LDAPConnectorConfig) (*ldapv3.Conn, error) {
	return dialLDAPWithTimeout(cfg, 15*time.Second)
}

func dialLDAPWithTimeout(cfg *LDAPConnectorConfig, operationTimeout time.Duration) (*ldapv3.Conn, error) {
	if operationTimeout <= 0 {
		return nil, fmt.Errorf("LDAP operation deadline exceeded")
	}
	dialTimeout := min(10*time.Second, operationTimeout)

	defaultPort := "636"
	if cfg.InsecureNoSSL {
		defaultPort = "389"
	}
	address, serverName, err := ldapDialAddress(cfg.Host, defaultPort)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	if cfg.InsecureNoSSL {
		conn, err := ldapv3.DialURL("ldap://"+address, ldapv3.DialWithDialer(dialer))
		if err != nil {
			return nil, err
		}
		conn.SetTimeout(operationTimeout)
		if cfg.StartTLS {
			tlsConfig, err := ldapTLSConfig(cfg, serverName)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			if err := conn.StartTLS(tlsConfig); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("StartTLS failed: %w", err)
			}
		}
		return conn, nil
	}

	tlsConfig, err := ldapTLSConfig(cfg, serverName)
	if err != nil {
		return nil, err
	}
	conn, err := ldapv3.DialURL(
		"ldaps://"+address,
		ldapv3.DialWithDialer(dialer),
		ldapv3.DialWithTLSConfig(tlsConfig),
	)
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(operationTimeout)
	return conn, nil
}

func ldapDialAddress(rawHost, defaultPort string) (address, serverName string, err error) {
	rawHost = strings.TrimSpace(rawHost)
	if rawHost == "" {
		return "", "", fmt.Errorf("LDAP host is required")
	}
	if strings.Contains(rawHost, "://") {
		return "", "", fmt.Errorf("LDAP host must not include a URL scheme")
	}

	if host, port, splitErr := net.SplitHostPort(rawHost); splitErr == nil {
		if host == "" || port == "" {
			return "", "", fmt.Errorf("invalid LDAP host %q", rawHost)
		}
		return net.JoinHostPort(host, port), strings.Trim(host, "[]"), nil
	}

	host := strings.Trim(rawHost, "[]")
	if net.ParseIP(host) == nil && strings.Contains(host, ":") {
		return "", "", fmt.Errorf("invalid LDAP host %q", rawHost)
	}
	return net.JoinHostPort(host, defaultPort), host, nil
}

func ldapTLSConfig(cfg *LDAPConnectorConfig, serverName string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: cfg.InsecureSkipVerify, // #nosec G402 -- explicit local-development option selected by the administrator
	}
	if strings.TrimSpace(cfg.RootCA) == "" {
		return tlsConfig, nil
	}

	certPool, err := x509.SystemCertPool()
	if err != nil || certPool == nil {
		certPool = x509.NewCertPool()
	}
	if ok := certPool.AppendCertsFromPEM([]byte(cfg.RootCA)); !ok {
		return nil, fmt.Errorf("LDAP root CA does not contain a valid PEM certificate")
	}
	tlsConfig.RootCAs = certPool
	return tlsConfig, nil
}

func ldapUIDFromEmail(email string) (string, error) {
	parts := strings.SplitN(strings.TrimSpace(email), "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("invalid email address")
	}
	return parts[0], nil
}

func ldapUserDN(uid, baseDN string) string {
	return fmt.Sprintf("uid=%s,%s", ldapv3.EscapeDN(uid), baseDN)
}

func ldapGroupDN(groupName, baseDN string) string {
	return fmt.Sprintf("cn=%s,%s", ldapv3.EscapeDN(groupName), baseDN)
}

func validateOpenLDAPUserProvisioningConfig(cfg *LDAPConnectorConfig) error {
	required := []struct {
		label    string
		actual   string
		expected string
	}{
		{label: "username", actual: cfg.UserSearchUsername, expected: "uid"},
		{label: "email", actual: cfg.UserSearchEmailAttr, expected: "mail"},
		{label: "name", actual: cfg.UserSearchNameAttr, expected: "cn"},
	}
	for _, attribute := range required {
		if !strings.EqualFold(strings.TrimSpace(attribute.actual), attribute.expected) {
			return fmt.Errorf("automatic OpenLDAP user provisioning requires %s attribute %q; configured %q directories must provision users upstream", attribute.label, attribute.expected, attribute.actual)
		}
	}
	if !isValidLDAPAttributeName(strings.TrimSpace(cfg.UserSearchIDAttr)) {
		return fmt.Errorf("automatic OpenLDAP user provisioning requires a valid stable user ID attribute")
	}
	return nil
}

// UpdateLDAPUserPassword changes a user's password in the LDAP directory.
// It first verifies the old password by attempting a bind, then uses the admin
// credentials to perform the password modification.
func UpdateLDAPUserPassword(cfg *LDAPConnectorConfig, uid, oldPassword, newPassword string) error {
	if cfg == nil {
		return fmt.Errorf("LDAP connector config is nil")
	}

	user, err := findLDAPUserWithAdminBind(cfg, cfg.UserSearchIDAttr, uid)
	if err != nil {
		return fmt.Errorf("failed to resolve LDAP user: %w", err)
	}
	userDN := user.DN

	verifyConn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer verifyConn.Close()

	if err := verifyConn.Bind(userDN, oldPassword); err != nil {
		return fmt.Errorf("current password is incorrect")
	}

	adminConn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer adminConn.Close()

	if err := adminConn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind as admin: %w", err)
	}

	modReq := ldapv3.NewModifyRequest(userDN, nil)
	modReq.Replace("userPassword", []string{newPassword})
	if err := adminConn.Modify(modReq); err != nil {
		return fmt.Errorf("failed to update LDAP password: %w", err)
	}

	return nil
}

// ResetLDAPUserPassword resets an LDAP user's password using admin bind (no old password required).
func ResetLDAPUserPassword(cfg *LDAPConnectorConfig, uid, newPassword string) error {
	if cfg == nil {
		return fmt.Errorf("LDAP connector config is nil")
	}

	user, err := findLDAPUserWithAdminBind(cfg, cfg.UserSearchIDAttr, uid)
	if err != nil {
		return fmt.Errorf("failed to resolve LDAP user: %w", err)
	}
	userDN := user.DN

	conn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind as admin: %w", err)
	}

	modReq := ldapv3.NewModifyRequest(userDN, nil)
	modReq.Replace("userPassword", []string{newPassword})
	if err := conn.Modify(modReq); err != nil {
		return fmt.Errorf("failed to reset LDAP password: %w", err)
	}

	return nil
}

// CheckUserInLDAPGroups checks if a user is a member of at least one of the required groups.
// Returns true if requiredGroups is empty (no restriction).
func CheckUserInLDAPGroups(cfg *LDAPConnectorConfig, email string) (bool, error) {
	if cfg == nil || len(cfg.RequiredGroups) == 0 {
		return true, nil
	}
	if cfg.GroupSearchBaseDN == "" {
		return false, fmt.Errorf("group search not configured but requiredGroups is set")
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return false, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return false, fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	user, err := findLDAPUser(conn, cfg, cfg.UserSearchEmailAttr, email)
	if err != nil {
		return false, err
	}

	groupAttr, err := configuredLDAPGroupAttribute(cfg)
	if err != nil {
		return false, err
	}
	membershipValue, err := ldapGroupMembershipValue(conn, cfg, user.DN)
	if err != nil {
		return false, err
	}
	for _, requiredGroup := range cfg.RequiredGroups {
		group, err := findLDAPGroup(conn, cfg, requiredGroup, []string{groupAttr})
		if errors.Is(err, ErrLDAPGroupNotFound) {
			continue
		}
		if err != nil {
			return false, err
		}
		member, err := conn.Compare(group.DN, groupAttr, membershipValue)
		if err != nil {
			return false, fmt.Errorf("failed to check LDAP group %q membership: %w", requiredGroup, err)
		}
		if member {
			return true, nil
		}
	}

	return false, nil
}

// ListLDAPGroups returns all group names from the LDAP directory under the configured group search base.
func ListLDAPGroups(cfg *LDAPConnectorConfig) ([]string, error) {
	if cfg == nil || cfg.GroupSearchBaseDN == "" {
		return nil, fmt.Errorf("LDAP group search not configured")
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return nil, fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	nameAttr := cfg.GroupSearchNameAttr
	if nameAttr == "" {
		nameAttr = "cn"
	}
	groupAttr, err := configuredLDAPGroupAttribute(cfg)
	if err != nil {
		return nil, err
	}
	groupFilter, err := configuredLDAPGroupSearchFilter(cfg, groupAttr)
	if err != nil {
		return nil, err
	}

	searchReq := ldapv3.NewSearchRequest(
		cfg.GroupSearchBaseDN,
		ldapv3.ScopeWholeSubtree, ldapv3.NeverDerefAliases, 0, 0, false,
		groupFilter,
		[]string{nameAttr},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP groups: %w", err)
	}

	groups := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		name := entry.GetAttributeValue(nameAttr)
		if name != "" {
			groups = append(groups, name)
		}
	}
	return groups, nil
}

// CreateLDAPGroup creates a new groupOfNames in the LDAP directory.
func CreateLDAPGroup(cfg *LDAPConnectorConfig, groupName string) error {
	if cfg == nil || cfg.GroupSearchBaseDN == "" {
		return fmt.Errorf("LDAP group search not configured")
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	groupAttr, err := configuredLDAPGroupAttribute(cfg)
	if err != nil {
		return err
	}
	if _, err := findLDAPGroup(conn, cfg, groupName, nil); err == nil {
		return fmt.Errorf("LDAP group %q already exists", groupName)
	} else if !errors.Is(err, ErrLDAPGroupNotFound) {
		return err
	}
	if err := validateLDAPGroupCreationConfig(cfg); err != nil {
		return err
	}
	dn := ldapGroupDN(groupName, cfg.GroupSearchBaseDN)
	addReq, err := newLDAPGroupAddRequest(dn, groupName, groupAttr, "")
	if err != nil {
		return err
	}

	if err := conn.Add(addReq); err != nil {
		return fmt.Errorf("failed to create LDAP group %q: %w", groupName, err)
	}
	return nil
}

// AddUserToLDAPGroups adds a user to the specified LDAP groups.
// Groups that don't exist will be created first.
func AddUserToLDAPGroups(cfg *LDAPConnectorConfig, email string, groupNames []string) error {
	if cfg == nil || cfg.GroupSearchBaseDN == "" || len(groupNames) == 0 {
		return nil
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	user, err := findLDAPUser(conn, cfg, cfg.UserSearchEmailAttr, email)
	if err != nil {
		return err
	}
	groupAttr, err := configuredLDAPGroupAttribute(cfg)
	if err != nil {
		return err
	}
	membershipValue, err := ldapGroupMembershipValue(conn, cfg, user.DN)
	if err != nil {
		return err
	}

	for _, groupName := range groupNames {
		group, err := findLDAPGroup(conn, cfg, groupName, []string{groupAttr, "objectClass"})
		if errors.Is(err, ErrLDAPGroupNotFound) {
			if err := validateLDAPGroupCreationConfig(cfg); err != nil {
				return err
			}
			groupDN := ldapGroupDN(groupName, cfg.GroupSearchBaseDN)
			// Group doesn't exist, create it with this user as first member
			addReq, err := newLDAPGroupAddRequest(groupDN, groupName, groupAttr, membershipValue)
			if err != nil {
				return err
			}
			if createErr := conn.Add(addReq); createErr != nil {
				return fmt.Errorf("failed to create LDAP group %q: %w", groupName, createErr)
			}
			continue
		} else if err != nil {
			return fmt.Errorf("failed to find LDAP group %q: %w", groupName, err)
		}
		groupDN := group.DN
		members := group.GetAttributeValues(groupAttr)

		// Group exists, check if user is already a member
		alreadyMember := false
		for _, m := range members {
			if strings.EqualFold(m, membershipValue) {
				alreadyMember = true
				break
			}
		}
		if alreadyMember {
			continue
		}

		// Add user to group
		modReq := ldapv3.NewModifyRequest(groupDN, nil)
		modReq.Add(groupAttr, []string{membershipValue})
		if err := conn.Modify(modReq); err != nil {
			return fmt.Errorf("failed to add user to LDAP group %q: %w", groupName, err)
		}

		// Remove the valid placeholder used to keep required-membership group
		// schemas valid while a group has no real members.
		placeholder := ldapEmptyGroupMembershipValue(groupDN, groupAttr)
		for _, m := range members {
			if placeholder != "" && strings.EqualFold(m, placeholder) {
				cleanReq := ldapv3.NewModifyRequest(groupDN, nil)
				cleanReq.Delete(groupAttr, []string{placeholder})
				if err := conn.Modify(cleanReq); err != nil {
					return fmt.Errorf("failed to remove placeholder from LDAP group %q: %w", groupName, err)
				}
				break
			}
		}
	}
	return nil
}

// RemoveUserFromLDAPGroups removes a user from all LDAP groups.
func RemoveUserFromLDAPGroups(cfg *LDAPConnectorConfig, email string) error {
	if cfg == nil || cfg.GroupSearchBaseDN == "" {
		return nil
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to LDAP: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return fmt.Errorf("failed to bind to LDAP: %w", err)
	}

	user, err := findLDAPUser(conn, cfg, cfg.UserSearchEmailAttr, email)
	if errors.Is(err, ErrLDAPUserNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return removeLDAPUserFromGroups(conn, cfg, user)
}

func removeLDAPUserFromGroups(conn *ldapv3.Conn, cfg *LDAPConnectorConfig, user *LDAPDirectoryUser) error {
	groupAttr, err := configuredLDAPGroupAttribute(cfg)
	if err != nil {
		return err
	}
	membershipValue, err := ldapGroupMembershipValue(conn, cfg, user.DN)
	if err != nil {
		return err
	}

	// Find all groups containing this user
	searchReq := ldapv3.NewSearchRequest(
		cfg.GroupSearchBaseDN,
		ldapv3.ScopeWholeSubtree, ldapv3.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(%s=%s)", groupAttr, ldapv3.EscapeFilter(membershipValue)),
		[]string{groupAttr, "objectClass"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return fmt.Errorf("failed to search groups for user: %w", err)
	}

	for _, entry := range result.Entries {
		if ldapGroupRequiresMember(entry) && !hasOtherLDAPGroupMember(entry.GetAttributeValues(groupAttr), membershipValue) {
			placeholder := ldapEmptyGroupMembershipValue(entry.DN, groupAttr)
			if placeholder == "" {
				return fmt.Errorf("LDAP group %q requires a member but attribute %q has no supported placeholder", entry.DN, groupAttr)
			}
			addPlaceholder := ldapv3.NewModifyRequest(entry.DN, nil)
			addPlaceholder.Add(groupAttr, []string{placeholder})
			if err := conn.Modify(addPlaceholder); err != nil {
				return fmt.Errorf("failed to preserve required member for LDAP group %q: %w", entry.DN, err)
			}
		}

		modReq := ldapv3.NewModifyRequest(entry.DN, nil)
		modReq.Delete(groupAttr, []string{membershipValue})
		if err := conn.Modify(modReq); err != nil {
			return fmt.Errorf("failed to remove user from LDAP group %q: %w", entry.DN, err)
		}
	}
	return nil
}

func configuredLDAPGroupAttribute(cfg *LDAPConnectorConfig) (string, error) {
	groupAttr := strings.TrimSpace(cfg.GroupSearchGroupAttr)
	if groupAttr == "" {
		groupAttr = "member"
	}
	if !isValidLDAPAttributeName(groupAttr) {
		return "", fmt.Errorf("invalid LDAP group membership attribute %q", groupAttr)
	}
	return groupAttr, nil
}

func configuredLDAPGroupNameAttribute(cfg *LDAPConnectorConfig) (string, error) {
	nameAttr := strings.TrimSpace(cfg.GroupSearchNameAttr)
	if nameAttr == "" {
		nameAttr = "cn"
	}
	if !isValidLDAPAttributeName(nameAttr) {
		return "", fmt.Errorf("invalid LDAP group name attribute %q", nameAttr)
	}
	return nameAttr, nil
}

func findLDAPGroup(conn *ldapv3.Conn, cfg *LDAPConnectorConfig, groupName string, attributes []string) (*ldapv3.Entry, error) {
	groupName = strings.TrimSpace(groupName)
	if groupName == "" {
		return nil, fmt.Errorf("LDAP group name is required")
	}
	nameAttr, err := configuredLDAPGroupNameAttribute(cfg)
	if err != nil {
		return nil, err
	}
	groupAttr, err := configuredLDAPGroupAttribute(cfg)
	if err != nil {
		return nil, err
	}
	baseFilter, err := configuredLDAPGroupSearchFilter(cfg, groupAttr)
	if err != nil {
		return nil, err
	}
	filter := fmt.Sprintf("(&%s(%s=%s))", baseFilter, nameAttr, ldapv3.EscapeFilter(groupName))
	result, err := conn.Search(ldapv3.NewSearchRequest(
		cfg.GroupSearchBaseDN,
		ldapv3.ScopeWholeSubtree,
		ldapv3.NeverDerefAliases,
		2,
		15,
		false,
		filter,
		uniqueLDAPAttributes(append(attributes, nameAttr)),
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to search LDAP group %q: %w", groupName, err)
	}
	if len(result.Entries) == 0 {
		return nil, ErrLDAPGroupNotFound
	}
	if len(result.Entries) != 1 {
		return nil, fmt.Errorf("LDAP group lookup for %q is ambiguous", groupName)
	}
	return result.Entries[0], nil
}

func configuredLDAPGroupSearchFilter(cfg *LDAPConnectorConfig, groupAttr string) (string, error) {
	if strings.TrimSpace(cfg.GroupSearchFilter) != "" {
		filter, err := normalizedLDAPFilter(cfg.GroupSearchFilter)
		if err != nil {
			return "", fmt.Errorf("invalid LDAP group filter: %w", err)
		}
		return filter, nil
	}
	objectClass, _, err := ldapGroupSchema(groupAttr)
	if err == nil {
		return fmt.Sprintf("(objectClass=%s)", ldapv3.EscapeFilter(objectClass)), nil
	}
	return fmt.Sprintf("(%s=*)", groupAttr), nil
}

func validateLDAPGroupCreationConfig(cfg *LDAPConnectorConfig) error {
	nameAttr, err := configuredLDAPGroupNameAttribute(cfg)
	if err != nil {
		return err
	}
	if !strings.EqualFold(nameAttr, "cn") {
		return fmt.Errorf("automatic LDAP group creation requires group name attribute cn; configured %q groups must be created in the directory first", nameAttr)
	}
	return nil
}

func ldapGroupMembershipValue(conn *ldapv3.Conn, cfg *LDAPConnectorConfig, userDN string) (string, error) {
	userAttr := strings.TrimSpace(cfg.GroupSearchUserAttr)
	if userAttr == "" || strings.EqualFold(userAttr, "DN") {
		return userDN, nil
	}
	if !isValidLDAPAttributeName(userAttr) {
		return "", fmt.Errorf("invalid LDAP group user attribute %q", userAttr)
	}
	searchReq := ldapv3.NewSearchRequest(
		userDN,
		ldapv3.ScopeBaseObject, ldapv3.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{userAttr},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("failed to read LDAP user attribute %q: %w", userAttr, err)
	}
	if len(result.Entries) != 1 {
		return "", fmt.Errorf("LDAP user %q was not found", userDN)
	}
	value := result.Entries[0].GetAttributeValue(userAttr)
	if value == "" {
		return "", fmt.Errorf("LDAP user %q has no %q attribute", userDN, userAttr)
	}
	return value, nil
}

func newLDAPGroupAddRequest(groupDN, groupName, groupAttr, membershipValue string) (*ldapv3.AddRequest, error) {
	objectClass, requiresMember, err := ldapGroupSchema(groupAttr)
	if err != nil {
		return nil, err
	}

	addReq := ldapv3.NewAddRequest(groupDN, nil)
	addReq.Attribute("objectClass", []string{objectClass})
	addReq.Attribute("cn", []string{groupName})
	if objectClass == "posixGroup" {
		addReq.Attribute("gidNumber", []string{fmt.Sprintf("%d", generateUIDNumber("group:"+strings.ToLower(groupName)))})
	}
	if membershipValue != "" {
		addReq.Attribute(groupAttr, []string{membershipValue})
	} else if requiresMember {
		addReq.Attribute(groupAttr, []string{ldapEmptyGroupMembershipValue(groupDN, groupAttr)})
	}
	return addReq, nil
}

func ldapGroupSchema(groupAttr string) (objectClass string, requiresMember bool, err error) {
	switch {
	case strings.EqualFold(groupAttr, "member"):
		return "groupOfNames", true, nil
	case strings.EqualFold(groupAttr, "uniqueMember"):
		return "groupOfUniqueNames", true, nil
	case strings.EqualFold(groupAttr, "memberUid"):
		return "posixGroup", false, nil
	default:
		return "", false, fmt.Errorf("cannot create LDAP group for unsupported membership attribute %q", groupAttr)
	}
}

func ldapEmptyGroupMembershipValue(groupDN, groupAttr string) string {
	if strings.EqualFold(groupAttr, "member") || strings.EqualFold(groupAttr, "uniqueMember") {
		return "cn=__netbird_empty__," + groupDN
	}
	return ""
}

func ldapGroupRequiresMember(entry *ldapv3.Entry) bool {
	for _, objectClass := range entry.GetAttributeValues("objectClass") {
		if strings.EqualFold(objectClass, "groupOfNames") || strings.EqualFold(objectClass, "groupOfUniqueNames") {
			return true
		}
	}
	return false
}

func hasOtherLDAPGroupMember(members []string, membershipValue string) bool {
	for _, member := range members {
		if strings.TrimSpace(member) != "" && !strings.EqualFold(member, membershipValue) {
			return true
		}
	}
	return false
}

func isValidLDAPAttributeName(attribute string) bool {
	if attribute == "" {
		return false
	}
	for _, char := range attribute {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func generateUIDNumber(uid string) int {
	h := 10000
	for _, c := range uid {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return (h % 55535) + 10000
}
