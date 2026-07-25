package outbound

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

type staticResolver map[string][]netip.Addr

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r[host], nil
}

type sequenceResolver struct {
	mu        sync.Mutex
	addresses [][]netip.Addr
}

func (r *sequenceResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	addresses := r.addresses[0]
	if len(r.addresses) > 1 {
		r.addresses = r.addresses[1:]
	}
	return addresses, nil
}

func TestValidatorRejectsPrivateAddressWithoutAllowlist(t *testing.T) {
	validator, err := NewValidator(staticResolver{"idp.internal": {netip.MustParseAddr("10.10.0.5")}}, nil, nil)
	require.NoError(t, err)

	_, err = validator.ValidateURL(context.Background(), mustURL(t, "https://idp.internal"))
	require.ErrorContains(t, err, "not allowlisted")
}

func TestValidatorAllowsExplicitPrivateCIDR(t *testing.T) {
	validator, err := NewValidator(staticResolver{"idp.internal": {netip.MustParseAddr("10.10.0.5")}}, []string{"10.10.0.0/16"}, nil)
	require.NoError(t, err)

	_, err = validator.ValidateURL(context.Background(), mustURL(t, "https://idp.internal"))
	require.NoError(t, err)
}

func TestValidatorRequiresAllowlistForSpecialUseInternalRanges(t *testing.T) {
	resolver := staticResolver{
		"cgnat.internal":     {netip.MustParseAddr("100.64.0.10")},
		"benchmark.internal": {netip.MustParseAddr("198.18.0.10")},
	}
	validator, err := NewValidator(resolver, nil, nil)
	require.NoError(t, err)

	_, err = validator.ValidateURL(context.Background(), mustURL(t, "https://cgnat.internal"))
	require.ErrorContains(t, err, "not allowlisted")
	_, err = validator.ValidateURL(context.Background(), mustURL(t, "https://benchmark.internal"))
	require.ErrorContains(t, err, "not allowlisted")

	validator, err = NewValidator(resolver, []string{"100.64.0.0/10"}, nil)
	require.NoError(t, err)
	_, err = validator.ValidateURL(context.Background(), mustURL(t, "https://cgnat.internal"))
	require.NoError(t, err)
}

func TestValidatorAllowsExplicitDomainSuffix(t *testing.T) {
	validator, err := NewValidator(staticResolver{"login.corp.example": {netip.MustParseAddr("192.168.1.2")}}, nil, []string{"corp.example"})
	require.NoError(t, err)

	_, err = validator.ValidateURL(context.Background(), mustURL(t, "https://login.corp.example"))
	require.NoError(t, err)
}

func TestValidatorRejectsUnsafeURLForms(t *testing.T) {
	validator, err := NewValidator(staticResolver{}, nil, nil)
	require.NoError(t, err)

	_, err = validator.ValidateURL(context.Background(), mustURL(t, "http://example.com"))
	require.ErrorContains(t, err, "HTTPS")

	_, err = validator.ValidateURL(context.Background(), mustURL(t, "https://user:pass@example.com"))
	require.ErrorContains(t, err, "credentials")
}

func TestValidatorRejectsIPv6PrivateAndMixedResolution(t *testing.T) {
	validator, err := NewValidator(staticResolver{
		"ipv6.internal": {netip.MustParseAddr("fd00::10")},
		"mixed.example": {
			netip.MustParseAddr("93.184.216.34"),
			netip.MustParseAddr("10.10.0.5"),
		},
	}, nil, nil)
	require.NoError(t, err)

	_, err = validator.ValidateURL(context.Background(), mustURL(t, "https://ipv6.internal"))
	require.ErrorContains(t, err, "not allowlisted")

	_, err = validator.ValidateURL(context.Background(), mustURL(t, "https://mixed.example"))
	require.ErrorContains(t, err, "not allowlisted")
}

func TestValidatorRejectsMetadataAndUnsafeRedirects(t *testing.T) {
	validator, err := NewValidator(staticResolver{
		"metadata.example": {netip.MustParseAddr("169.254.169.254")},
	}, nil, nil)
	require.NoError(t, err)

	_, err = validator.ValidateURL(context.Background(), mustURL(t, "https://metadata.example/latest/meta-data"))
	require.ErrorContains(t, err, "not routable")

	redirect, err := http.NewRequest(http.MethodGet, "http://public.example/callback", nil)
	require.NoError(t, err)
	err = validator.HTTPClient().CheckRedirect(redirect, nil)
	require.ErrorContains(t, err, "HTTPS")
}

func TestHTTPClientRejectsDNSRebindingBeforeDial(t *testing.T) {
	resolver := &sequenceResolver{addresses: [][]netip.Addr{
		{netip.MustParseAddr("93.184.216.34")},
		{netip.MustParseAddr("127.0.0.1")},
	}}
	validator, err := NewValidator(resolver, nil, nil)
	require.NoError(t, err)

	target := mustURL(t, "https://rebind.example")
	_, err = validator.ValidateURL(context.Background(), target)
	require.NoError(t, err)

	request, err := http.NewRequest(http.MethodGet, target.String(), nil)
	require.NoError(t, err)
	_, err = validator.HTTPClient().Do(request)
	require.ErrorContains(t, err, "forbidden address")
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	return parsed
}
