package edr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	edrmodel "github.com/netbirdio/netbird/management/server/localintegrations/edr/model"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	maxProviderResponse  = 16 << 20
	maxProviderPages     = 100
	maxProviderDevices   = 100_000
	maxProviderClockSkew = 5 * time.Minute
)

type httpDoer interface {
	Do(request *http.Request) (*http.Response, error)
}

type deviceSnapshot struct {
	ExternalID   string
	SerialNumber string
	Hostname     string
	Compliant    bool
	Reason       string
	LastSeenAt   time.Time
}

type deviceIdentityFilter struct {
	serialNumbers map[string]struct{}
	hostnames     map[string]struct{}
}

func newDeviceIdentityFilter() *deviceIdentityFilter {
	return &deviceIdentityFilter{
		serialNumbers: make(map[string]struct{}),
		hostnames:     make(map[string]struct{}),
	}
}

func (f *deviceIdentityFilter) add(serialNumber, hostname string) {
	if f == nil {
		return
	}
	if serialNumber = normalizeIdentity(serialNumber); serialNumber != "" {
		f.serialNumbers[serialNumber] = struct{}{}
	}
	if hostname = normalizeIdentity(hostname); hostname != "" {
		f.hostnames[hostname] = struct{}{}
	}
}

func (f *deviceIdentityFilter) matches(serialNumber, hostname string) bool {
	if f == nil {
		return true
	}
	if _, ok := f.serialNumbers[normalizeIdentity(serialNumber)]; ok {
		return true
	}
	_, ok := f.hostnames[normalizeIdentity(hostname)]
	return ok
}

func (s *Service) fetchProviderDevices(
	ctx context.Context,
	provider string,
	config *providerConfig,
	filter *deviceIdentityFilter,
) ([]deviceSnapshot, error) {
	var snapshots []deviceSnapshot
	var err error
	switch provider {
	case providerIntune:
		snapshots, err = s.fetchIntuneDevices(ctx, config)
	case providerSentinelOne:
		snapshots, err = s.fetchSentinelOneDevices(ctx, config)
	case providerFalcon:
		snapshots, err = s.fetchFalconDevices(ctx, config)
	case providerHuntress:
		snapshots, err = s.fetchHuntressDevices(ctx, config)
	case providerFleetDM:
		snapshots, err = s.fetchFleetDMDevices(ctx, config, filter)
	default:
		return nil, fmt.Errorf("unsupported EDR provider %q", provider)
	}
	if err != nil {
		return nil, err
	}
	return filterSnapshots(snapshots, filter), nil
}

func (s *Service) fetchIntuneDevices(ctx context.Context, config *providerConfig) ([]deviceSnapshot, error) {
	tokenURL := "https://login.microsoftonline.com/" + url.PathEscape(config.TenantID) + "/oauth2/v2.0/token"
	form := url.Values{
		"client_id":     {config.ClientID},
		"client_secret": {config.Secret},
		"grant_type":    {"client_credentials"},
		"scope":         {"https://graph.microsoft.com/.default"},
	}
	request, err := s.newProviderRequest(
		ctx,
		http.MethodPost,
		tokenURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("create Intune token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := s.doProviderJSON(request, &tokenResponse); err != nil {
		return nil, fmt.Errorf("authenticate with Intune: %w", err)
	}
	if tokenResponse.AccessToken == "" {
		return nil, errors.New("intune authentication returned an empty access token")
	}

	nextURL := "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices" +
		"?$select=id,deviceName,operatingSystem,complianceState,osVersion,model,manufacturer,serialNumber,azureADDeviceId,lastSyncDateTime"
	var snapshots []deviceSnapshot
	pages := 0
	for page := 0; nextURL != "" && page < maxProviderPages; page++ {
		pages++
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create Intune device request: %w", err)
		}
		request.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
		var response struct {
			Value []struct {
				ID               string    `json:"id"`
				DeviceName       string    `json:"deviceName"`
				ComplianceState  string    `json:"complianceState"`
				SerialNumber     string    `json:"serialNumber"`
				AzureADDeviceID  string    `json:"azureADDeviceId"`
				LastSyncDateTime time.Time `json:"lastSyncDateTime"`
			} `json:"value"`
			Next string `json:"@odata.nextLink"`
		}
		if err := s.doProviderJSON(request, &response); err != nil {
			return nil, fmt.Errorf("list Intune managed devices: %w", err)
		}
		for _, device := range response.Value {
			compliant := strings.EqualFold(device.ComplianceState, "compliant") &&
				recentEnough(device.LastSyncDateTime, config.LastSyncedInterval)
			reason := ""
			if !strings.EqualFold(device.ComplianceState, "compliant") {
				reason = "Intune device is not compliant"
			} else if !recentEnough(device.LastSyncDateTime, config.LastSyncedInterval) {
				reason = "Intune device has not synchronized recently"
			}
			externalID := firstNonEmpty(device.ID, device.AzureADDeviceID, device.SerialNumber, device.DeviceName)
			snapshots = append(snapshots, deviceSnapshot{
				ExternalID:   externalID,
				SerialNumber: normalizeIdentity(device.SerialNumber),
				Hostname:     normalizeIdentity(device.DeviceName),
				Compliant:    compliant,
				Reason:       reason,
				LastSeenAt:   device.LastSyncDateTime,
			})
		}
		if len(snapshots) > maxProviderDevices {
			return nil, fmt.Errorf("intune returned more than %d devices", maxProviderDevices)
		}
		if response.Next != "" {
			next, err := url.Parse(response.Next)
			if err != nil || !strings.EqualFold(next.Hostname(), "graph.microsoft.com") {
				return nil, errors.New("intune returned an invalid pagination URL")
			}
		}
		nextURL = response.Next
	}
	if nextURL != "" && pages == maxProviderPages {
		return nil, fmt.Errorf("intune pagination exceeded %d pages", maxProviderPages)
	}
	return normalizeSnapshots(snapshots), nil
}

func (s *Service) fetchSentinelOneDevices(ctx context.Context, config *providerConfig) ([]deviceSnapshot, error) {
	nextCursor := ""
	var snapshots []deviceSnapshot
	for page := 0; page < maxProviderPages; page++ {
		query := url.Values{"limit": {"1000"}}
		if nextCursor != "" {
			query.Set("cursor", nextCursor)
		}
		endpoint := config.APIURL + "/web/api/v2.1/agents?" + query.Encode()
		request, err := s.newProviderRequest(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("create SentinelOne request: %w", err)
		}
		request.Header.Set("Authorization", "ApiToken "+config.APIToken)
		var response struct {
			Data       []map[string]any `json:"data"`
			Pagination struct {
				NextCursor string `json:"nextCursor"`
			} `json:"pagination"`
		}
		if err := s.doProviderJSON(request, &response); err != nil {
			return nil, fmt.Errorf("list SentinelOne agents: %w", err)
		}
		for _, agent := range response.Data {
			lastSeen := mapTime(agent, "lastActiveDate", "lastActiveAt", "updatedAt")
			compliant, reason := sentinelOneCompliant(agent, config.SentinelOneMatch, lastSeen, config.LastSyncedInterval)
			snapshots = append(snapshots, deviceSnapshot{
				ExternalID: firstNonEmpty(
					mapString(agent, "id"),
					mapString(agent, "uuid"),
					mapString(agent, "serialNumber"),
					mapString(agent, "computerName"),
				),
				SerialNumber: normalizeIdentity(mapString(agent, "serialNumber")),
				Hostname:     normalizeIdentity(firstNonEmpty(mapString(agent, "computerName"), mapString(agent, "hostName"))),
				Compliant:    compliant,
				Reason:       reason,
				LastSeenAt:   lastSeen,
			})
		}
		if len(snapshots) > maxProviderDevices {
			return nil, fmt.Errorf("SentinelOne returned more than %d agents", maxProviderDevices)
		}
		nextCursor = response.Pagination.NextCursor
		if nextCursor == "" {
			break
		}
	}
	if nextCursor != "" {
		return nil, fmt.Errorf("SentinelOne pagination exceeded %d pages", maxProviderPages)
	}
	return normalizeSnapshots(snapshots), nil
}

func (s *Service) fetchFalconDevices(ctx context.Context, config *providerConfig) ([]deviceSnapshot, error) {
	baseURL, ok := falconCloudURLs[config.CloudID]
	if !ok {
		return nil, fmt.Errorf("unsupported CrowdStrike cloud %q", config.CloudID)
	}
	form := url.Values{
		"client_id":     {config.ClientID},
		"client_secret": {config.Secret},
	}
	tokenRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		baseURL+"/oauth2/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("create CrowdStrike token request: %w", err)
	}
	tokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := s.doProviderJSON(tokenRequest, &tokenResponse); err != nil {
		return nil, fmt.Errorf("authenticate with CrowdStrike: %w", err)
	}
	if tokenResponse.AccessToken == "" {
		return nil, errors.New("CrowdStrike authentication returned an empty access token")
	}

	deviceIDs, err := s.fetchFalconDeviceIDs(ctx, baseURL, tokenResponse.AccessToken)
	if err != nil {
		return nil, err
	}

	var snapshots []deviceSnapshot
	for start := 0; start < len(deviceIDs); start += 100 {
		end := min(start+100, len(deviceIDs))
		payload, err := json.Marshal(map[string]any{"ids": deviceIDs[start:end]})
		if err != nil {
			return nil, fmt.Errorf("encode CrowdStrike device request: %w", err)
		}
		detailsRequest, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			baseURL+"/devices/entities/devices/v2",
			bytes.NewReader(payload),
		)
		if err != nil {
			return nil, fmt.Errorf("create CrowdStrike device details request: %w", err)
		}
		detailsRequest.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
		detailsRequest.Header.Set("Content-Type", "application/json")
		var details struct {
			Resources []map[string]any `json:"resources"`
		}
		if err := s.doProviderJSON(detailsRequest, &details); err != nil {
			return nil, fmt.Errorf("get CrowdStrike device details: %w", err)
		}
		scores := map[string]int{}
		if config.ZTAScoreThreshold > 0 {
			scoreQuery := url.Values{}
			for _, deviceID := range deviceIDs[start:end] {
				scoreQuery.Add("ids", deviceID)
			}
			scoreRequest, err := http.NewRequestWithContext(
				ctx,
				http.MethodGet,
				baseURL+"/zero-trust-assessment/entities/assessments/v1?"+scoreQuery.Encode(),
				nil,
			)
			if err != nil {
				return nil, fmt.Errorf("create CrowdStrike ZTA request: %w", err)
			}
			scoreRequest.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
			var assessments struct {
				Resources []map[string]any `json:"resources"`
			}
			if err := s.doProviderJSON(scoreRequest, &assessments); err != nil {
				return nil, fmt.Errorf("get CrowdStrike ZTA assessments: %w", err)
			}
			for _, assessment := range assessments.Resources {
				score := mapInt(assessment, "score")
				if details := mapObject(assessment, "assessment"); len(details) > 0 {
					score = mapInt(details, "overall")
				}
				scores[firstNonEmpty(mapString(assessment, "aid"), mapString(assessment, "device_id"))] =
					score
			}
		}
		for _, device := range details.Resources {
			id := firstNonEmpty(mapString(device, "device_id"), mapString(device, "id"))
			score := scores[id]
			compliant := config.ZTAScoreThreshold == 0 || score >= config.ZTAScoreThreshold
			reason := ""
			if !compliant {
				reason = fmt.Sprintf(
					"CrowdStrike ZTA score %d is below required score %d",
					score,
					config.ZTAScoreThreshold,
				)
			}
			snapshots = append(snapshots, deviceSnapshot{
				ExternalID:   firstNonEmpty(id, mapString(device, "serial_number"), mapString(device, "hostname")),
				SerialNumber: normalizeIdentity(mapString(device, "serial_number")),
				Hostname:     normalizeIdentity(mapString(device, "hostname")),
				Compliant:    compliant,
				Reason:       reason,
				LastSeenAt:   mapTime(device, "last_seen", "modified_timestamp"),
			})
		}
	}
	return normalizeSnapshots(snapshots), nil
}

func (s *Service) fetchFalconDeviceIDs(
	ctx context.Context,
	baseURL, accessToken string,
) ([]string, error) {
	var deviceIDs []string
	seen := make(map[string]struct{})
	offset := ""
	for page := 0; page < maxProviderPages; page++ {
		query := url.Values{"limit": {"10000"}}
		if offset != "" {
			query.Set("offset", offset)
		}
		request, err := http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			baseURL+"/devices/queries/devices-scroll/v1?"+query.Encode(),
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("create CrowdStrike device query: %w", err)
		}
		request.Header.Set("Authorization", "Bearer "+accessToken)
		var response struct {
			Resources []string `json:"resources"`
			Meta      struct {
				Pagination struct {
					Offset any `json:"offset"`
					Total  int `json:"total"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		if err := s.doProviderJSON(request, &response); err != nil {
			return nil, fmt.Errorf("list CrowdStrike device IDs: %w", err)
		}
		for _, deviceID := range response.Resources {
			deviceID = strings.TrimSpace(deviceID)
			if deviceID == "" {
				continue
			}
			if _, exists := seen[deviceID]; exists {
				continue
			}
			seen[deviceID] = struct{}{}
			deviceIDs = append(deviceIDs, deviceID)
		}
		if len(deviceIDs) > maxProviderDevices {
			return nil, fmt.Errorf("CrowdStrike returned more than %d devices", maxProviderDevices)
		}
		if len(response.Resources) == 0 ||
			(response.Meta.Pagination.Total > 0 && len(deviceIDs) >= response.Meta.Pagination.Total) {
			return deviceIDs, nil
		}
		nextOffset := scalarString(response.Meta.Pagination.Offset)
		if nextOffset == "" || nextOffset == offset {
			return nil, errors.New("CrowdStrike returned an invalid pagination offset")
		}
		offset = nextOffset
	}
	return nil, fmt.Errorf("CrowdStrike pagination exceeded %d pages", maxProviderPages)
}

func (s *Service) fetchHuntressDevices(ctx context.Context, config *providerConfig) ([]deviceSnapshot, error) {
	const baseURL = "https://api.huntress.io/v1"
	var snapshots []deviceSnapshot
	hasNext := false
	for page := 1; page <= maxProviderPages; page++ {
		request, err := http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			baseURL+"/agents?page="+strconv.Itoa(page)+"&limit=500",
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("create Huntress request: %w", err)
		}
		request.Header.Set(
			"Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(config.APIKey+":"+config.APISecret)),
		)
		var raw json.RawMessage
		if err := s.doProviderJSON(request, &raw); err != nil {
			return nil, fmt.Errorf("list Huntress agents: %w", err)
		}
		agents, next, err := decodeHuntressAgents(raw)
		if err != nil {
			return nil, err
		}
		hasNext = next
		for _, agent := range agents {
			lastSeen := mapTime(agent, "last_seen_at", "last_seen", "updated_at")
			compliant, reason := huntressCompliant(agent, config.HuntressMatch, lastSeen, config.LastSyncedInterval)
			snapshots = append(snapshots, deviceSnapshot{
				ExternalID: firstNonEmpty(
					mapString(agent, "id"),
					mapString(agent, "agent_id"),
					mapString(agent, "serial_number"),
					mapString(agent, "hostname"),
				),
				SerialNumber: normalizeIdentity(firstNonEmpty(mapString(agent, "serial_number"), mapString(agent, "system_serial_number"))),
				Hostname:     normalizeIdentity(firstNonEmpty(mapString(agent, "hostname"), mapString(agent, "computer_name"))),
				Compliant:    compliant,
				Reason:       reason,
				LastSeenAt:   lastSeen,
			})
		}
		if len(snapshots) > maxProviderDevices {
			return nil, fmt.Errorf("huntress returned more than %d agents", maxProviderDevices)
		}
		if !hasNext || len(agents) == 0 {
			break
		}
	}
	if hasNext {
		return nil, fmt.Errorf("huntress pagination exceeded %d pages", maxProviderPages)
	}
	return normalizeSnapshots(snapshots), nil
}

func (s *Service) fetchFleetDMDevices(
	ctx context.Context,
	config *providerConfig,
	filter *deviceIdentityFilter,
) ([]deviceSnapshot, error) {
	var hosts []map[string]any
	hasNext := false
	for page := 0; page < maxProviderPages; page++ {
		request, err := s.newProviderRequest(
			ctx,
			http.MethodGet,
			config.APIURL+"/api/v1/fleet/hosts?per_page=500&page="+strconv.Itoa(page),
			nil,
		)
		if err != nil {
			return nil, fmt.Errorf("create FleetDM request: %w", err)
		}
		request.Header.Set("Authorization", "Bearer "+config.APIToken)
		var response struct {
			Hosts []map[string]any `json:"hosts"`
			Meta  struct {
				HasNextResults bool `json:"has_next_results"`
			} `json:"meta"`
		}
		if err := s.doProviderJSON(request, &response); err != nil {
			return nil, fmt.Errorf("list FleetDM hosts: %w", err)
		}
		hosts = append(hosts, response.Hosts...)
		if len(hosts) > maxProviderDevices {
			return nil, fmt.Errorf("FleetDM returned more than %d hosts", maxProviderDevices)
		}
		hasNext = response.Meta.HasNextResults
		if !hasNext || len(response.Hosts) == 0 {
			break
		}
	}
	if hasNext {
		return nil, fmt.Errorf("FleetDM pagination exceeded %d pages", maxProviderPages)
	}

	hosts = slices.DeleteFunc(hosts, func(host map[string]any) bool {
		return !filter.matches(
			mapString(host, "hardware_serial"),
			mapString(host, "hostname"),
		)
	})
	if fleetDMNeedsHealthData(config.FleetDMMatch) {
		if err := s.enrichFleetDMHostsWithHealth(ctx, config, hosts); err != nil {
			return nil, err
		}
	}

	snapshots := make([]deviceSnapshot, 0, len(hosts))
	for _, host := range hosts {
		lastSeen := mapTime(host, "seen_time", "updated_at")
		compliant, reason := fleetDMCompliant(host, config.FleetDMMatch, lastSeen, config.LastSyncedInterval)
		snapshots = append(snapshots, deviceSnapshot{
			ExternalID: firstNonEmpty(
				mapString(host, "uuid"),
				mapString(host, "id"),
				mapString(host, "hardware_serial"),
				mapString(host, "hostname"),
			),
			SerialNumber: normalizeIdentity(mapString(host, "hardware_serial")),
			Hostname:     normalizeIdentity(mapString(host, "hostname")),
			Compliant:    compliant,
			Reason:       reason,
			LastSeenAt:   lastSeen,
		})
	}
	return normalizeSnapshots(snapshots), nil
}

func fleetDMNeedsHealthData(match api.FleetDMMatchAttributes) bool {
	return match.DiskEncryptionEnabled != nil ||
		match.FailingPoliciesCountMax != nil ||
		match.VulnerableSoftwareCountMax != nil ||
		(match.RequiredPolicies != nil && len(*match.RequiredPolicies) > 0)
}

func (s *Service) enrichFleetDMHostsWithHealth(
	ctx context.Context,
	config *providerConfig,
	hosts []map[string]any,
) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("enrich FleetDM hosts with health: %w", err)
	}
	type healthLookup struct {
		host   map[string]any
		hostID string
		health map[string]any
	}
	lookups := make([]healthLookup, 0, len(hosts))
	for index, host := range hosts {
		hostID, ok := mapIntValue(host, "id")
		if !ok || hostID <= 0 {
			return fmt.Errorf("FleetDM host at index %d has an invalid id for health lookup", index)
		}
		lookups = append(lookups, healthLookup{
			host:   host,
			hostID: strconv.Itoa(hostID),
		})
	}

	group, groupCtx := errgroup.WithContext(ctx)
	concurrency := s.fleetDMHealthConcurrency
	if concurrency <= 0 {
		concurrency = defaultFleetDMHealthConcurrency
	}
	group.SetLimit(concurrency)
	for index := range lookups {
		if groupCtx.Err() != nil {
			break
		}
		lookup := &lookups[index]
		group.Go(func() error {
			request, err := s.newProviderRequest(
				groupCtx,
				http.MethodGet,
				config.APIURL+"/api/v1/fleet/hosts/"+url.PathEscape(lookup.hostID)+"/health",
				nil,
			)
			if err != nil {
				return fmt.Errorf("create FleetDM host %s health request: %w", lookup.hostID, err)
			}
			request.Header.Set("Authorization", "Bearer "+config.APIToken)

			var response struct {
				HostID any            `json:"host_id"`
				Health map[string]any `json:"health"`
			}
			if err := s.doProviderJSON(request, &response); err != nil {
				return fmt.Errorf("get FleetDM host %s health: %w", lookup.hostID, err)
			}
			if len(response.Health) == 0 {
				return fmt.Errorf("FleetDM host %s returned no health data", lookup.hostID)
			}
			responseHostID := scalarString(response.HostID)
			if responseHostID != "" && responseHostID != lookup.hostID {
				return fmt.Errorf(
					"FleetDM host %s returned health data for host %s",
					lookup.hostID,
					responseHostID,
				)
			}
			lookup.health = response.Health
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return fmt.Errorf("enrich FleetDM hosts with health: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("enrich FleetDM hosts with health: %w", err)
	}

	for _, lookup := range lookups {
		for key, value := range lookup.health {
			lookup.host[key] = value
		}
	}
	return nil
}

func (s *Service) doProviderJSON(request *http.Request, target any) error {
	if _, err := s.outbound.ValidateURL(request.Context(), request.URL); err != nil {
		return fmt.Errorf("outbound destination rejected: %w", err)
	}
	response, err := s.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("EDR provider request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return fmt.Errorf("EDR provider returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxProviderResponse))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode EDR provider response: %w", err)
	}
	return nil
}

func (s *Service) newProviderRequest(
	ctx context.Context,
	method, rawURL string,
	body io.Reader,
) (*http.Request, error) {
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse EDR provider URL: %w", err)
	}
	if _, err := s.outbound.ValidateURL(ctx, target); err != nil {
		return nil, fmt.Errorf("outbound destination rejected: %w", err)
	}
	// #nosec G704 -- outbound.ValidateURL rejects non-HTTPS, credentials,
	// private destinations and DNS-rebinding before the request is built.
	return http.NewRequestWithContext(ctx, method, target.String(), body)
}

func sentinelOneCompliant(
	agent map[string]any,
	match api.SentinelOneMatchAttributes,
	lastSeen time.Time,
	maxAgeHours int,
) (bool, string) {
	if !recentEnough(lastSeen, maxAgeHours) {
		return false, "SentinelOne agent has not synchronized recently"
	}
	if match.ActiveThreats != nil {
		actual, ok := mapIntValue(agent, "activeThreats")
		if !ok || actual > *match.ActiveThreats {
			return false, "SentinelOne agent has too many active threats"
		}
	}
	booleanChecks := []struct {
		expected *bool
		field    string
		reason   string
	}{
		{match.EncryptedApplications, "encryptedApplications", "SentinelOne disk encryption state does not match"},
		{match.FirewallEnabled, "firewallEnabled", "SentinelOne firewall state does not match"},
		{match.Infected, "infected", "SentinelOne infection state does not match"},
		{match.IsActive, "isActive", "SentinelOne active state does not match"},
		{match.IsUpToDate, "isUpToDate", "SentinelOne update state does not match"},
	}
	for _, check := range booleanChecks {
		if check.expected == nil {
			continue
		}
		actual, ok := mapBoolValue(agent, check.field)
		if !ok || actual != *check.expected {
			return false, check.reason
		}
	}
	if match.NetworkStatus != nil {
		actual, ok := mapStringValue(agent, "networkStatus")
		if !ok || !strings.EqualFold(actual, string(*match.NetworkStatus)) {
			return false, "SentinelOne network state does not match"
		}
	}
	if match.OperationalState != nil {
		actual, ok := mapStringValue(agent, "operationalState")
		if !ok || !strings.EqualFold(actual, *match.OperationalState) {
			return false, "SentinelOne operational state does not match"
		}
	}
	return true, ""
}

func huntressCompliant(
	agent map[string]any,
	match api.HuntressMatchAttributes,
	lastSeen time.Time,
	maxAgeHours int,
) (bool, string) {
	if !recentEnough(lastSeen, maxAgeHours) {
		return false, "Huntress agent has not synchronized recently"
	}
	checks := []struct {
		expected *string
		actual   string
		reason   string
	}{
		{match.DefenderPolicyStatus, mapString(agent, "defender_policy_status"), "Huntress Defender policy state does not match"},
		{match.DefenderStatus, mapString(agent, "defender_status"), "Huntress Defender state does not match"},
		{match.DefenderSubstatus, mapString(agent, "defender_substatus"), "Huntress Defender substatus does not match"},
		{match.FirewallStatus, mapString(agent, "firewall_status"), "Huntress firewall state does not match"},
	}
	for _, check := range checks {
		if check.expected != nil && !strings.EqualFold(check.actual, *check.expected) {
			return false, check.reason
		}
	}
	return true, ""
}

func fleetDMCompliant(
	host map[string]any,
	match api.FleetDMMatchAttributes,
	lastSeen time.Time,
	maxAgeHours int,
) (bool, string) {
	if !recentEnough(lastSeen, maxAgeHours) {
		return false, "FleetDM host has not synchronized recently"
	}
	if match.DiskEncryptionEnabled != nil {
		actual, ok := mapBoolValue(host, "disk_encryption_enabled")
		if !ok || actual != *match.DiskEncryptionEnabled {
			return false, "FleetDM disk encryption state does not match"
		}
	}
	if match.StatusOnline != nil {
		status, ok := mapStringValue(host, "status")
		online := strings.EqualFold(status, "online")
		if !ok || online != *match.StatusOnline {
			return false, "FleetDM online state does not match"
		}
	}
	if match.FailingPoliciesCountMax != nil {
		count, ok := mapIntValue(host, "failing_policies_count")
		if !ok || count > *match.FailingPoliciesCountMax {
			return false, "FleetDM host has too many failing policies"
		}
	}
	if match.VulnerableSoftwareCountMax != nil {
		vulnerableSoftware, ok := mapSliceValue(host, "vulnerable_software")
		if !ok || len(vulnerableSoftware) > *match.VulnerableSoftwareCountMax {
			return false, "FleetDM host has too much vulnerable software"
		}
	}
	if match.RequiredPolicies != nil && len(*match.RequiredPolicies) > 0 {
		failingPolicies, ok := fleetDMFailingPolicyIDs(host)
		if !ok {
			return false, "FleetDM failing policy state is unavailable"
		}
		failing := intSet(failingPolicies)
		for _, policyID := range *match.RequiredPolicies {
			if _, failed := failing[policyID]; failed {
				return false, fmt.Sprintf("FleetDM required policy %d is failing", policyID)
			}
		}
	}
	return true, ""
}

func fleetDMFailingPolicyIDs(host map[string]any) ([]int, bool) {
	rawPolicies, ok := mapSliceValue(host, "failing_policies")
	if !ok {
		return nil, false
	}
	policyIDs := make([]int, 0, len(rawPolicies))
	for _, rawPolicy := range rawPolicies {
		policy, ok := rawPolicy.(map[string]any)
		if !ok {
			return nil, false
		}
		policyID, ok := mapIntValue(policy, "id")
		if !ok {
			return nil, false
		}
		policyIDs = append(policyIDs, policyID)
	}
	return policyIDs, true
}

func decodeHuntressAgents(raw json.RawMessage) ([]map[string]any, bool, error) {
	var direct []map[string]any
	if err := json.Unmarshal(raw, &direct); err == nil {
		return direct, len(direct) > 0, nil
	}
	var wrapped struct {
		Agents     []map[string]any `json:"agents"`
		Data       []map[string]any `json:"data"`
		NextPage   any              `json:"next_page"`
		TotalPages int              `json:"total_pages"`
		Page       int              `json:"page"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, false, fmt.Errorf("decode Huntress agents: %w", err)
	}
	agents := wrapped.Agents
	if agents == nil {
		agents = wrapped.Data
	}
	hasNext := wrapped.NextPage != nil || (wrapped.TotalPages > 0 && wrapped.Page < wrapped.TotalPages)
	return agents, hasNext, nil
}

func normalizeSnapshots(input []deviceSnapshot) []deviceSnapshot {
	result := make([]deviceSnapshot, 0, len(input))
	seen := make(map[string]struct{}, len(input))
	for _, snapshot := range input {
		snapshot.ExternalID = strings.TrimSpace(snapshot.ExternalID)
		snapshot.SerialNumber = normalizeIdentity(snapshot.SerialNumber)
		snapshot.Hostname = normalizeIdentity(snapshot.Hostname)
		if snapshot.ExternalID == "" || (snapshot.SerialNumber == "" && snapshot.Hostname == "") {
			continue
		}
		if _, ok := seen[snapshot.ExternalID]; ok {
			continue
		}
		seen[snapshot.ExternalID] = struct{}{}
		result = append(result, snapshot)
	}
	return result
}

func filterSnapshots(
	input []deviceSnapshot,
	filter *deviceIdentityFilter,
) []deviceSnapshot {
	if filter == nil {
		return input
	}
	return slices.DeleteFunc(input, func(snapshot deviceSnapshot) bool {
		return !filter.matches(snapshot.SerialNumber, snapshot.Hostname)
	})
}

func snapshotsToModels(snapshots []deviceSnapshot) []*edrmodel.Device {
	result := make([]*edrmodel.Device, 0, len(snapshots))
	for _, snapshot := range snapshots {
		result = append(result, &edrmodel.Device{
			ExternalID:   snapshot.ExternalID,
			SerialNumber: snapshot.SerialNumber,
			Hostname:     snapshot.Hostname,
			Compliant:    snapshot.Compliant,
			Reason:       snapshot.Reason,
			LastSeenAt:   snapshot.LastSeenAt,
		})
	}
	return result
}

func recentEnough(value time.Time, maxAgeHours int) bool {
	now := time.Now().UTC()
	return !value.IsZero() &&
		!value.After(now.Add(maxProviderClockSkew)) &&
		value.After(now.Add(-time.Duration(maxAgeHours)*time.Hour))
}

func normalizeIdentity(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func mapString(values map[string]any, keys ...string) string {
	value, _ := mapStringValue(values, keys...)
	return value
}

func mapStringValue(values map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		switch value := values[key].(type) {
		case string:
			return strings.TrimSpace(value), true
		case json.Number:
			return value.String(), true
		case float64:
			return strconv.FormatInt(int64(value), 10), true
		}
	}
	return "", false
}

func mapInt(values map[string]any, keys ...string) int {
	value, _ := mapIntValue(values, keys...)
	return value
}

func mapIntValue(values map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		switch value := values[key].(type) {
		case float64:
			return int(value), true
		case json.Number:
			parsed, err := value.Int64()
			return int(parsed), err == nil
		case string:
			parsed, err := strconv.Atoi(value)
			return parsed, err == nil
		}
	}
	return 0, false
}

func mapBoolValue(values map[string]any, key string) (bool, bool) {
	switch value := values[key].(type) {
	case bool:
		return value, true
	case string:
		parsed, err := strconv.ParseBool(value)
		return parsed, err == nil
	default:
		return false, false
	}
}

func mapTime(values map[string]any, keys ...string) time.Time {
	for _, key := range keys {
		value := mapString(values, key)
		if value == "" {
			continue
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999"} {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed.UTC()
			}
		}
	}
	return time.Time{}
}

func mapObject(values map[string]any, key string) map[string]any {
	object, _ := mapObjectValue(values, key)
	return object
}

func mapObjectValue(values map[string]any, key string) (map[string]any, bool) {
	if object, ok := values[key].(map[string]any); ok {
		return object, true
	}
	return map[string]any{}, false
}

func mapSliceValue(values map[string]any, key string) ([]any, bool) {
	raw, ok := values[key].([]any)
	return raw, ok
}

func scalarString(value any) string {
	switch item := value.(type) {
	case string:
		return strings.TrimSpace(item)
	case json.Number:
		return item.String()
	case float64:
		return strconv.FormatInt(int64(item), 10)
	default:
		return ""
	}
}

func intSet(values []int) map[int]struct{} {
	result := make(map[int]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

var falconCloudURLs = map[string]string{
	"us-1":     "https://api.crowdstrike.com",
	"us-2":     "https://api.us-2.crowdstrike.com",
	"eu-1":     "https://api.eu-1.crowdstrike.com",
	"us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
	"us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
}
