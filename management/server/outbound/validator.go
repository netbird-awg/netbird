package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	allowCIDRsEnv          = "NB_OUTBOUND_ALLOW_PRIVATE_CIDRS"
	allowDomainSuffixesEnv = "NB_OUTBOUND_ALLOW_DOMAIN_SUFFIXES"
)

var restrictedNetworkPrefixes = []netip.Prefix{
	// Carrier-grade NAT and benchmark ranges are frequently used for internal
	// service networks but are not classified as private by netip.Addr.
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
}

// Resolver is the subset of net.Resolver used by Validator.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Validator validates outbound HTTPS destinations and pins each connection to
// an address that was checked before dialing. Private destinations require an
// explicit CIDR or domain-suffix allowlist entry.
type Validator struct {
	resolver        Resolver
	allowedCIDRs    []netip.Prefix
	allowedSuffixes []string
	dialTimeout     time.Duration
	requestTimeout  time.Duration
}

// NewValidatorFromEnv builds a validator from comma-separated allowlists.
func NewValidatorFromEnv() (*Validator, error) {
	return NewValidator(
		net.DefaultResolver,
		strings.Split(os.Getenv(allowCIDRsEnv), ","),
		strings.Split(os.Getenv(allowDomainSuffixesEnv), ","),
	)
}

// NewValidator builds a validator with explicit dependencies for testing.
func NewValidator(resolver Resolver, cidrs, suffixes []string) (*Validator, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	allowedCIDRs := make([]netip.Prefix, 0, len(cidrs))
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid outbound private CIDR %q: %w", raw, err)
		}
		allowedCIDRs = append(allowedCIDRs, prefix.Masked())
	}

	allowedSuffixes := make([]string, 0, len(suffixes))
	for _, raw := range suffixes {
		raw = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if raw != "" {
			allowedSuffixes = append(allowedSuffixes, raw)
		}
	}

	return &Validator{
		resolver:        resolver,
		allowedCIDRs:    allowedCIDRs,
		allowedSuffixes: allowedSuffixes,
		dialTimeout:     5 * time.Second,
		requestTimeout:  10 * time.Second,
	}, nil
}

// ValidateURL validates the URL and every currently resolved address.
func (v *Validator) ValidateURL(ctx context.Context, target *url.URL) ([]netip.Addr, error) {
	if target == nil {
		return nil, fmt.Errorf("outbound URL is required")
	}
	if !strings.EqualFold(target.Scheme, "https") {
		return nil, fmt.Errorf("outbound URL must use HTTPS")
	}
	if target.User != nil {
		return nil, fmt.Errorf("outbound URL must not contain credentials")
	}
	host := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
	if host == "" {
		return nil, fmt.Errorf("outbound URL host is required")
	}

	addresses, err := v.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve outbound host: %w", err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("outbound host did not resolve to an address")
	}

	domainAllowed := v.domainAllowed(host)
	for _, address := range addresses {
		if err := v.validateAddress(address.Unmap(), domainAllowed); err != nil {
			return nil, fmt.Errorf("outbound host %q resolved to a forbidden address: %w", host, err)
		}
	}
	return addresses, nil
}

// HTTPClient returns an HTTP client that validates every redirect and pins
// connections to the validated DNS response to prevent DNS-rebinding bypasses.
func (v *Validator) HTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: v.dialTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("parse outbound address: %w", err)
			}
			target := &url.URL{Scheme: "https", Host: net.JoinHostPort(host, port)}
			addresses, err := v.ValidateURL(ctx, target)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, ip := range addresses {
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, fmt.Errorf("connect to validated outbound host: %w", lastErr)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   v.requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many outbound redirects")
			}
			_, err := v.ValidateURL(req.Context(), req.URL)
			return err
		},
	}
}

func (v *Validator) domainAllowed(host string) bool {
	for _, suffix := range v.allowedSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func (v *Validator) validateAddress(address netip.Addr, domainAllowed bool) error {
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return fmt.Errorf("address %s is not routable", address)
	}
	if !address.IsPrivate() && !isRestrictedNetworkAddress(address) {
		return nil
	}
	if domainAllowed {
		return nil
	}
	for _, prefix := range v.allowedCIDRs {
		if prefix.Contains(address) {
			return nil
		}
	}
	return fmt.Errorf("private or restricted address %s is not allowlisted", address)
}

func isRestrictedNetworkAddress(address netip.Addr) bool {
	for _, prefix := range restrictedNetworkPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
