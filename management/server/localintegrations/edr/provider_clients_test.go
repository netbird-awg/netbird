package edr

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	edrmodel "github.com/netbirdio/netbird/management/server/localintegrations/edr/model"
	"github.com/netbirdio/netbird/management/server/outbound"
	api "github.com/netbirdio/netbird/shared/management/http/api"
)

type providerTestResolver map[string][]netip.Addr

func (r providerTestResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r[host], nil
}

type providerTestDoer func(*http.Request) (*http.Response, error)

func (f providerTestDoer) Do(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestSentinelOneCompliance(t *testing.T) {
	zero := 0
	required := true
	network := api.SentinelOneMatchAttributesNetworkStatusConnected
	match := api.SentinelOneMatchAttributes{
		ActiveThreats:   &zero,
		FirewallEnabled: &required,
		NetworkStatus:   &network,
	}
	agent := map[string]any{
		"activeThreats":   float64(0),
		"firewallEnabled": true,
		"networkStatus":   "connected",
	}
	compliant, reason := sentinelOneCompliant(agent, match, time.Now().UTC(), 24)
	require.True(t, compliant)
	require.Empty(t, reason)

	agent["activeThreats"] = float64(1)
	compliant, reason = sentinelOneCompliant(agent, match, time.Now().UTC(), 24)
	require.False(t, compliant)
	require.Contains(t, reason, "active threats")
}

func TestSentinelOneComplianceFailsClosedForMissingAttributes(t *testing.T) {
	zero := 0
	expectedFalse := false
	recent := time.Now().UTC()

	compliant, reason := sentinelOneCompliant(
		map[string]any{},
		api.SentinelOneMatchAttributes{ActiveThreats: &zero},
		recent,
		24,
	)
	require.False(t, compliant)
	require.Contains(t, reason, "active threats")

	compliant, reason = sentinelOneCompliant(
		map[string]any{},
		api.SentinelOneMatchAttributes{Infected: &expectedFalse},
		recent,
		24,
	)
	require.False(t, compliant)
	require.Contains(t, reason, "infection state")
}

func TestFleetDMCompliance(t *testing.T) {
	zero := 0
	required := true
	requiredPolicies := []int{7}
	match := api.FleetDMMatchAttributes{
		DiskEncryptionEnabled:   &required,
		FailingPoliciesCountMax: &zero,
		RequiredPolicies:        &requiredPolicies,
		StatusOnline:            &required,
	}
	host := map[string]any{
		"disk_encryption_enabled": true,
		"status":                  "online",
		"failing_policies_count":  float64(0),
		"failing_policies":        []any{},
	}
	compliant, reason := fleetDMCompliant(host, match, time.Now().UTC(), 24)
	require.True(t, compliant)
	require.Empty(t, reason)

	host["failing_policies"] = []any{map[string]any{"id": float64(7)}}
	compliant, reason = fleetDMCompliant(host, match, time.Now().UTC(), 24)
	require.False(t, compliant)
	require.Contains(t, reason, "policy 7")
}

func TestFleetDMComplianceFailsClosedForMissingAttributes(t *testing.T) {
	zero := 0
	expectedFalse := false
	recent := time.Now().UTC()

	compliant, reason := fleetDMCompliant(
		map[string]any{},
		api.FleetDMMatchAttributes{FailingPoliciesCountMax: &zero},
		recent,
		24,
	)
	require.False(t, compliant)
	require.Contains(t, reason, "failing policies")

	compliant, reason = fleetDMCompliant(
		map[string]any{},
		api.FleetDMMatchAttributes{DiskEncryptionEnabled: &expectedFalse},
		recent,
		24,
	)
	require.False(t, compliant)
	require.Contains(t, reason, "disk encryption")

	compliant, reason = fleetDMCompliant(
		map[string]any{},
		api.FleetDMMatchAttributes{VulnerableSoftwareCountMax: &zero},
		recent,
		24,
	)
	require.False(t, compliant)
	require.Contains(t, reason, "vulnerable software")

	requiredPolicies := []int{7}
	compliant, reason = fleetDMCompliant(
		map[string]any{},
		api.FleetDMMatchAttributes{RequiredPolicies: &requiredPolicies},
		recent,
		24,
	)
	require.False(t, compliant)
	require.Contains(t, reason, "policy state is unavailable")
}

func TestFleetDMComplianceUsesHealthReportFields(t *testing.T) {
	one := 1
	two := 2
	requiredPolicies := []int{9}
	host := map[string]any{
		"failing_policies_count": float64(1),
		"failing_policies": []any{
			map[string]any{"id": float64(7)},
		},
		"vulnerable_software": []any{
			map[string]any{"id": float64(11)},
			map[string]any{"id": float64(12)},
		},
	}
	match := api.FleetDMMatchAttributes{
		FailingPoliciesCountMax:    &one,
		VulnerableSoftwareCountMax: &two,
		RequiredPolicies:           &requiredPolicies,
	}

	compliant, reason := fleetDMCompliant(host, match, time.Now().UTC(), 24)
	require.True(t, compliant)
	require.Empty(t, reason)

	zero := 0
	match.VulnerableSoftwareCountMax = &zero
	compliant, reason = fleetDMCompliant(host, match, time.Now().UTC(), 24)
	require.False(t, compliant)
	require.Contains(t, reason, "vulnerable software")
}

func TestEnrichFleetDMHostsWithHealth(t *testing.T) {
	validator, err := outbound.NewValidator(
		providerTestResolver{"fleet.example": {netip.MustParseAddr("203.0.113.10")}},
		nil,
		nil,
	)
	require.NoError(t, err)

	service := &Service{
		outbound: validator,
		httpClient: providerTestDoer(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodGet {
				return nil, fmt.Errorf("unexpected method %s", request.Method)
			}
			if authorization := request.Header.Get("Authorization"); authorization != "Bearer fleet-token" {
				return nil, fmt.Errorf("unexpected authorization header %q", authorization)
			}
			if request.URL.Path != "/api/v1/fleet/hosts/42/health" {
				return nil, fmt.Errorf("unexpected path %q", request.URL.Path)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader(`{
					"host_id": 42,
					"health": {
						"disk_encryption_enabled": true,
						"failing_policies_count": 0,
						"failing_policies": [],
						"vulnerable_software": []
					}
				}`)),
			}, nil
		}),
	}
	hosts := []map[string]any{{"id": float64(42), "status": "online"}}

	err = service.enrichFleetDMHostsWithHealth(
		context.Background(),
		&providerConfig{APIURL: "https://fleet.example", APIToken: "fleet-token"},
		hosts,
	)
	require.NoError(t, err)
	require.Equal(t, true, hosts[0]["disk_encryption_enabled"])
	require.Equal(t, float64(0), hosts[0]["failing_policies_count"])
}

func TestEnrichFleetDMHostsWithHealthHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := (&Service{}).enrichFleetDMHostsWithHealth(ctx, &providerConfig{}, nil)
	require.ErrorIs(t, err, context.Canceled)
}

func TestFleetDMNeedsHealthData(t *testing.T) {
	required := []int{7}
	require.False(t, fleetDMNeedsHealthData(api.FleetDMMatchAttributes{}))
	require.False(t, fleetDMNeedsHealthData(api.FleetDMMatchAttributes{RequiredPolicies: &[]int{}}))
	require.True(t, fleetDMNeedsHealthData(api.FleetDMMatchAttributes{RequiredPolicies: &required}))
}

func TestNormalizeSnapshotsRejectsUnmatchableAndDuplicateDevices(t *testing.T) {
	snapshots := normalizeSnapshots([]deviceSnapshot{
		{ExternalID: "one", SerialNumber: " ABC "},
		{ExternalID: "one", Hostname: "duplicate"},
		{ExternalID: "two"},
		{ExternalID: "three", Hostname: " Device.Example "},
	})
	require.Len(t, snapshots, 2)
	require.Equal(t, "abc", snapshots[0].SerialNumber)
	require.Equal(t, "device.example", snapshots[1].Hostname)
}

func TestUniqueDeviceIndexesRejectsAmbiguousIdentity(t *testing.T) {
	devices := []edrmodel.Device{
		{SerialNumber: "duplicate", Hostname: "first"},
		{SerialNumber: "duplicate", Hostname: "second"},
		{SerialNumber: "unique", Hostname: "third"},
	}
	indexes, duplicates := uniqueDeviceIndexes(devices, func(device edrmodel.Device) string {
		return device.SerialNumber
	})
	require.NotContains(t, indexes, "duplicate")
	require.Contains(t, duplicates, "duplicate")
	require.Equal(t, 2, indexes["unique"])
}

func TestRetryDelayIsBounded(t *testing.T) {
	require.Equal(t, time.Minute, retryDelay(1))
	require.Equal(t, time.Hour, retryDelay(100))
}

func TestDeviceIdentityFilterKeepsOnlyScopedDevices(t *testing.T) {
	filter := newDeviceIdentityFilter()
	filter.add("SERIAL-1", "Peer-One")
	filter.add("", "peer-two")

	filtered := filterSnapshots([]deviceSnapshot{
		{ExternalID: "one", SerialNumber: "serial-1", Hostname: "other"},
		{ExternalID: "two", Hostname: "PEER-TWO"},
		{ExternalID: "outside", SerialNumber: "serial-3", Hostname: "peer-three"},
	}, filter)

	require.Len(t, filtered, 2)
	require.Equal(t, []string{"one", "two"}, []string{filtered[0].ExternalID, filtered[1].ExternalID})
}

func TestRecentEnoughRejectsFutureProviderTimestamps(t *testing.T) {
	require.True(t, recentEnough(time.Now().UTC().Add(-time.Hour), 24))
	require.False(t, recentEnough(time.Now().UTC().Add(time.Hour), 24))
	require.False(t, recentEnough(time.Time{}, 24))
}
