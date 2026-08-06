package edr

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"

	api "github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/util/crypt"
)

const (
	providerFalcon      = "falcon"
	providerIntune      = "intune"
	providerSentinelOne = "sentinelone"
	providerHuntress    = "huntress"
	providerFleetDM     = "fleetdm"

	minLastSyncHours  = 24
	maxLastSyncHours  = 24 * 365
	maxCredentialSize = 4096
	maxURLSize        = 2048
)

var providers = []string{
	providerFalcon,
	providerIntune,
	providerSentinelOne,
	providerHuntress,
	providerFleetDM,
}

type providerConfig struct {
	ClientID           string                         `json:"client_id,omitempty"`
	Secret             string                         `json:"secret,omitempty"`
	TenantID           string                         `json:"tenant_id,omitempty"`
	CloudID            string                         `json:"cloud_id,omitempty"`
	APIURL             string                         `json:"api_url,omitempty"`
	APIToken           string                         `json:"api_token,omitempty"`
	APIKey             string                         `json:"api_key,omitempty"`
	APISecret          string                         `json:"api_secret,omitempty"`
	LastSyncedInterval int                            `json:"last_synced_interval,omitempty"`
	ZTAScoreThreshold  int                            `json:"zta_score_threshold,omitempty"`
	SentinelOneMatch   api.SentinelOneMatchAttributes `json:"sentinelone_match,omitempty"`
	HuntressMatch      api.HuntressMatchAttributes    `json:"huntress_match,omitempty"`
	FleetDMMatch       api.FleetDMMatchAttributes     `json:"fleetdm_match,omitempty"`
}

func configFromIntune(request api.EDRIntuneRequest, previous *providerConfig) (*providerConfig, bool, error) {
	config := &providerConfig{
		ClientID:           strings.TrimSpace(request.ClientId),
		Secret:             keepPrevious(request.Secret, previousValue(previous, func(c *providerConfig) string { return c.Secret })),
		TenantID:           strings.TrimSpace(request.TenantId),
		LastSyncedInterval: request.LastSyncedInterval,
	}
	if err := validateRequired(config.ClientID, "client_id"); err != nil {
		return nil, false, err
	}
	if err := validateRequired(config.TenantID, "tenant_id"); err != nil {
		return nil, false, err
	}
	if err := validateCredential(config.Secret, "secret"); err != nil {
		return nil, false, err
	}
	if err := validateLastSyncInterval(config.LastSyncedInterval); err != nil {
		return nil, false, err
	}
	return config, enabledValue(request.Enabled), nil
}

func configFromFalcon(request api.EDRFalconRequest, previous *providerConfig) (*providerConfig, bool, error) {
	config := &providerConfig{
		ClientID:          keepPrevious(request.ClientId, previousValue(previous, func(c *providerConfig) string { return c.ClientID })),
		Secret:            keepPrevious(request.Secret, previousValue(previous, func(c *providerConfig) string { return c.Secret })),
		CloudID:           strings.ToLower(strings.TrimSpace(request.CloudId)),
		ZTAScoreThreshold: request.ZtaScoreThreshold,
	}
	if err := validateCredential(config.ClientID, "client_id"); err != nil {
		return nil, false, err
	}
	if err := validateCredential(config.Secret, "secret"); err != nil {
		return nil, false, err
	}
	if !slices.Contains([]string{"eu-1", "us-1", "us-2", "us-gov-1", "us-gov-2"}, config.CloudID) {
		return nil, false, status.Errorf(status.InvalidArgument, "unsupported CrowdStrike cloud_id")
	}
	if config.ZTAScoreThreshold < 0 || config.ZTAScoreThreshold > 100 {
		return nil, false, status.Errorf(status.InvalidArgument, "zta_score_threshold must be between 0 and 100")
	}
	return config, enabledValue(request.Enabled), nil
}

func configFromSentinelOne(request api.EDRSentinelOneRequest, previous *providerConfig) (*providerConfig, bool, error) {
	config := &providerConfig{
		APIURL:             normalizeBaseURL(request.ApiUrl),
		APIToken:           keepPrevious(request.ApiToken, previousValue(previous, func(c *providerConfig) string { return c.APIToken })),
		LastSyncedInterval: request.LastSyncedInterval,
		SentinelOneMatch:   request.MatchAttributes,
	}
	if err := validateBaseURL(config.APIURL); err != nil {
		return nil, false, err
	}
	if err := validateCredential(config.APIToken, "api_token"); err != nil {
		return nil, false, err
	}
	if err := validateLastSyncInterval(config.LastSyncedInterval); err != nil {
		return nil, false, err
	}
	if err := validateSentinelOneMatch(config.SentinelOneMatch); err != nil {
		return nil, false, err
	}
	return config, enabledValue(request.Enabled), nil
}

func configFromHuntress(request api.EDRHuntressRequest, previous *providerConfig) (*providerConfig, bool, error) {
	config := &providerConfig{
		APIKey:             keepPrevious(request.ApiKey, previousValue(previous, func(c *providerConfig) string { return c.APIKey })),
		APISecret:          keepPrevious(request.ApiSecret, previousValue(previous, func(c *providerConfig) string { return c.APISecret })),
		LastSyncedInterval: request.LastSyncedInterval,
		HuntressMatch:      request.MatchAttributes,
	}
	if err := validateCredential(config.APIKey, "api_key"); err != nil {
		return nil, false, err
	}
	if err := validateCredential(config.APISecret, "api_secret"); err != nil {
		return nil, false, err
	}
	if err := validateLastSyncInterval(config.LastSyncedInterval); err != nil {
		return nil, false, err
	}
	for _, item := range []*string{
		config.HuntressMatch.DefenderPolicyStatus,
		config.HuntressMatch.DefenderStatus,
		config.HuntressMatch.DefenderSubstatus,
		config.HuntressMatch.FirewallStatus,
	} {
		if item != nil && (strings.TrimSpace(*item) == "" || len(*item) > 128) {
			return nil, false, status.Errorf(status.InvalidArgument, "invalid Huntress match attribute")
		}
	}
	return config, enabledValue(request.Enabled), nil
}

func configFromFleetDM(request api.EDRFleetDMRequest, previous *providerConfig) (*providerConfig, bool, error) {
	config := &providerConfig{
		APIURL:             normalizeBaseURL(request.ApiUrl),
		APIToken:           keepPrevious(request.ApiToken, previousValue(previous, func(c *providerConfig) string { return c.APIToken })),
		LastSyncedInterval: request.LastSyncedInterval,
		FleetDMMatch:       request.MatchAttributes,
	}
	if err := validateBaseURL(config.APIURL); err != nil {
		return nil, false, err
	}
	if err := validateCredential(config.APIToken, "api_token"); err != nil {
		return nil, false, err
	}
	if err := validateLastSyncInterval(config.LastSyncedInterval); err != nil {
		return nil, false, err
	}
	if config.FleetDMMatch.FailingPoliciesCountMax != nil && *config.FleetDMMatch.FailingPoliciesCountMax < 0 {
		return nil, false, status.Errorf(status.InvalidArgument, "failing_policies_count_max must not be negative")
	}
	if config.FleetDMMatch.VulnerableSoftwareCountMax != nil && *config.FleetDMMatch.VulnerableSoftwareCountMax < 0 {
		return nil, false, status.Errorf(status.InvalidArgument, "vulnerable_software_count_max must not be negative")
	}
	if config.FleetDMMatch.RequiredPolicies != nil {
		seen := make(map[int]struct{}, len(*config.FleetDMMatch.RequiredPolicies))
		for _, policyID := range *config.FleetDMMatch.RequiredPolicies {
			if policyID <= 0 {
				return nil, false, status.Errorf(status.InvalidArgument, "required FleetDM policy IDs must be positive")
			}
			if _, ok := seen[policyID]; ok {
				return nil, false, status.Errorf(status.InvalidArgument, "required FleetDM policy IDs must be unique")
			}
			seen[policyID] = struct{}{}
		}
	}
	return config, enabledValue(request.Enabled), nil
}

func validateSentinelOneMatch(match api.SentinelOneMatchAttributes) error {
	if match.ActiveThreats != nil && *match.ActiveThreats < 0 {
		return status.Errorf(status.InvalidArgument, "active_threats must not be negative")
	}
	if match.NetworkStatus != nil && !match.NetworkStatus.Valid() {
		return status.Errorf(status.InvalidArgument, "invalid SentinelOne network_status")
	}
	if match.OperationalState != nil &&
		(strings.TrimSpace(*match.OperationalState) == "" || len(*match.OperationalState) > 128) {
		return status.Errorf(status.InvalidArgument, "invalid SentinelOne operational_state")
	}
	return nil
}

func validateRequired(value, field string) error {
	if strings.TrimSpace(value) == "" || len(value) > maxCredentialSize {
		return status.Errorf(status.InvalidArgument, "%s is required", field)
	}
	return nil
}

func validateCredential(value, field string) error {
	if err := validateRequired(value, field); err != nil {
		return err
	}
	if strings.ContainsAny(value, "\r\n") {
		return status.Errorf(status.InvalidArgument, "%s is invalid", field)
	}
	return nil
}

func validateLastSyncInterval(value int) error {
	if value < minLastSyncHours || value > maxLastSyncHours {
		return status.Errorf(
			status.InvalidArgument,
			"last_synced_interval must be between %d and %d hours",
			minLastSyncHours,
			maxLastSyncHours,
		)
	}
	return nil
}

func normalizeBaseURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func validateBaseURL(raw string) error {
	if raw == "" || len(raw) > maxURLSize {
		return status.Errorf(status.InvalidArgument, "invalid EDR API URL")
	}
	target, err := url.ParseRequestURI(raw)
	if err != nil || target.Host == "" || !strings.EqualFold(target.Scheme, "https") {
		return status.Errorf(status.InvalidArgument, "EDR API URL must be an absolute HTTPS URL")
	}
	if target.User != nil || target.RawQuery != "" || target.Fragment != "" {
		return status.Errorf(status.InvalidArgument, "EDR API URL must not contain credentials, a query, or a fragment")
	}
	return nil
}

func enabledValue(enabled *bool) bool {
	return enabled == nil || *enabled
}

func keepPrevious(value, previous string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return previous
	}
	return value
}

func previousValue(previous *providerConfig, getter func(*providerConfig) string) string {
	if previous == nil {
		return ""
	}
	return getter(previous)
}

func encryptProviderConfig(encryptor *crypt.FieldEncrypt, config *providerConfig) (string, error) {
	// #nosec G117 -- the serialized credential payload is encrypted
	// immediately and is never persisted or returned in plaintext.
	payload, err := json.Marshal(config)
	if err != nil {
		return "", status.Errorf(status.Internal, "failed to encode EDR configuration")
	}
	encrypted, err := encryptor.Encrypt(string(payload))
	if err != nil {
		return "", status.Errorf(status.Internal, "failed to encrypt EDR configuration")
	}
	return encrypted, nil
}

func decryptProviderConfig(encryptor *crypt.FieldEncrypt, encrypted string) (*providerConfig, error) {
	plain, err := encryptor.Decrypt(encrypted)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to decrypt EDR configuration")
	}
	var config providerConfig
	if err := json.Unmarshal([]byte(plain), &config); err != nil {
		return nil, status.Errorf(status.Internal, "invalid stored EDR configuration")
	}
	return &config, nil
}
