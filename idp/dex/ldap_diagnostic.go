package dex

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"
)

const ldapDiagnosticTimeout = 15 * time.Second

// LDAPDiagnostic contains sanitized, stage-level connection results.
type LDAPDiagnostic struct {
	Checks   map[string]string
	Latency  time.Duration
	TestedAt time.Time
}

// LDAPDiagnosticError identifies the failed stage without exposing LDAP
// credentials, directory entries, or complete search results.
type LDAPDiagnosticError struct {
	Stage  string
	Code   string
	Checks map[string]string
	Err    error
}

func (e *LDAPDiagnosticError) Error() string {
	return fmt.Sprintf("LDAP %s check failed", e.Stage)
}

func (e *LDAPDiagnosticError) Unwrap() error {
	return e.Err
}

// TestLDAPConnection performs DNS, TCP, TLS, bind, user-search, and optional
// group-search diagnostics against a saved LDAP connector.
func TestLDAPConnection(ctx context.Context, cfg *LDAPConnectorConfig) (*LDAPDiagnostic, error) {
	if cfg == nil {
		return nil, &LDAPDiagnosticError{Stage: "config", Code: "ldap_config_missing", Err: fmt.Errorf("LDAP connector config is nil")}
	}
	ctx, cancel := context.WithTimeout(ctx, ldapDiagnosticTimeout)
	defer cancel()

	started := time.Now()
	checks := map[string]string{
		"dns":          "pending",
		"tcp":          "pending",
		"tls":          "pending",
		"bind":         "pending",
		"user_search":  "pending",
		"group_search": "pending",
	}

	defaultPort := "636"
	if cfg.InsecureNoSSL {
		defaultPort = "389"
	}
	address, host, err := ldapDialAddress(cfg.Host, defaultPort)
	if err != nil {
		return nil, diagnosticFailure(checks, "dns", "ldap_host_invalid", err)
	}

	if net.ParseIP(host) == nil {
		if _, err := net.DefaultResolver.LookupIPAddr(ctx, host); err != nil {
			return nil, diagnosticFailure(checks, "dns", "ldap_dns_failed", err)
		}
	}
	checks["dns"] = "ok"

	rawConn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, diagnosticFailure(checks, "tcp", "ldap_tcp_failed", err)
	}
	_ = rawConn.Close()
	checks["tcp"] = "ok"

	operationTimeout, err := remainingDiagnosticTimeout(ctx)
	if err != nil {
		return nil, diagnosticFailure(checks, "tls", "ldap_diagnostic_timeout", err)
	}
	conn, err := dialLDAPWithTimeout(cfg, operationTimeout)
	if err != nil {
		stage := "tls"
		code := "ldap_tls_failed"
		if cfg.InsecureNoSSL && !cfg.StartTLS {
			stage = "tcp"
			code = "ldap_connect_failed"
		}
		return nil, diagnosticFailure(checks, stage, code, err)
	}
	defer conn.Close()
	if cfg.InsecureNoSSL && !cfg.StartTLS {
		checks["tls"] = "skipped"
	} else {
		checks["tls"] = "ok"
	}

	operationTimeout, err = remainingDiagnosticTimeout(ctx)
	if err != nil {
		return nil, diagnosticFailure(checks, "bind", "ldap_diagnostic_timeout", err)
	}
	conn.SetTimeout(operationTimeout)
	if err := conn.Bind(cfg.BindDN, cfg.BindPW); err != nil {
		return nil, diagnosticFailure(checks, "bind", "ldap_bind_failed", err)
	}
	checks["bind"] = "ok"

	operationTimeout, err = remainingDiagnosticTimeout(ctx)
	if err != nil {
		return nil, diagnosticFailure(checks, "user_search", "ldap_diagnostic_timeout", err)
	}
	conn.SetTimeout(operationTimeout)
	if err := diagnosticLDAPSearch(conn, cfg.UserSearchBaseDN, cfg.UserSearchFilter); err != nil {
		return nil, diagnosticFailure(checks, "user_search", "ldap_user_search_failed", err)
	}
	checks["user_search"] = "ok"

	if strings.TrimSpace(cfg.GroupSearchBaseDN) == "" {
		checks["group_search"] = "skipped"
	} else {
		operationTimeout, err = remainingDiagnosticTimeout(ctx)
		if err != nil {
			return nil, diagnosticFailure(checks, "group_search", "ldap_diagnostic_timeout", err)
		}
		conn.SetTimeout(operationTimeout)
		if err := diagnosticLDAPSearch(conn, cfg.GroupSearchBaseDN, cfg.GroupSearchFilter); err != nil {
			return nil, diagnosticFailure(checks, "group_search", "ldap_group_search_failed", err)
		}
		checks["group_search"] = "ok"
	}

	return &LDAPDiagnostic{Checks: checks, Latency: time.Since(started), TestedAt: time.Now().UTC()}, nil
}

func remainingDiagnosticTimeout(ctx context.Context) (time.Duration, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ldapDiagnosticTimeout, nil
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, context.DeadlineExceeded
	}
	return remaining, nil
}

func diagnosticLDAPSearch(conn *ldapv3.Conn, baseDN, configuredFilter string) error {
	if strings.TrimSpace(baseDN) == "" {
		return fmt.Errorf("search base DN is required")
	}
	filter := strings.TrimSpace(configuredFilter)
	if filter == "" {
		filter = "(objectClass=*)"
	}
	if _, err := ldapv3.CompileFilter(filter); err != nil {
		return fmt.Errorf("invalid LDAP search filter: %w", err)
	}
	result, err := conn.Search(ldapv3.NewSearchRequest(
		baseDN,
		ldapv3.ScopeWholeSubtree,
		ldapv3.NeverDerefAliases,
		1,
		5,
		false,
		filter,
		[]string{"dn"},
		nil,
	))
	// A server can return LDAPResultSizeLimitExceeded together with the single
	// requested entry when more matches exist. For a bounded diagnostic probe,
	// that proves the search base/filter are usable and is therefore success.
	if err != nil && !ldapv3.IsErrorWithCode(err, ldapv3.LDAPResultSizeLimitExceeded) {
		return err
	}
	if result != nil && len(result.Entries) > 1 {
		return fmt.Errorf("LDAP diagnostic returned more entries than requested")
	}
	return nil
}

func diagnosticFailure(checks map[string]string, stage, code string, err error) *LDAPDiagnosticError {
	checks[stage] = "failed"
	copyOfChecks := make(map[string]string, len(checks))
	for key, value := range checks {
		copyOfChecks[key] = value
	}
	return &LDAPDiagnosticError{Stage: stage, Code: code, Checks: copyOfChecks, Err: err}
}
