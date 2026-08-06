package edr

import api "github.com/netbirdio/netbird/shared/management/http/api"

func intuneRequestFromUpdate(request api.EDRIntuneUpdateRequest) api.EDRIntuneRequest {
	return api.EDRIntuneRequest{
		ClientId:           request.ClientId,
		Enabled:            request.Enabled,
		Groups:             request.Groups,
		LastSyncedInterval: request.LastSyncedInterval,
		Secret:             optionalString(request.Secret),
		TenantId:           request.TenantId,
	}
}

func falconRequestFromUpdate(request api.EDRFalconUpdateRequest) api.EDRFalconRequest {
	return api.EDRFalconRequest{
		ClientId:          optionalString(request.ClientId),
		CloudId:           request.CloudId,
		Enabled:           request.Enabled,
		Groups:            request.Groups,
		Secret:            optionalString(request.Secret),
		ZtaScoreThreshold: request.ZtaScoreThreshold,
	}
}

func sentinelOneRequestFromUpdate(request api.EDRSentinelOneUpdateRequest) api.EDRSentinelOneRequest {
	return api.EDRSentinelOneRequest{
		ApiToken:           optionalString(request.ApiToken),
		ApiUrl:             request.ApiUrl,
		Enabled:            request.Enabled,
		Groups:             request.Groups,
		LastSyncedInterval: request.LastSyncedInterval,
		MatchAttributes:    request.MatchAttributes,
	}
}

func huntressRequestFromUpdate(request api.EDRHuntressUpdateRequest) api.EDRHuntressRequest {
	return api.EDRHuntressRequest{
		ApiKey:             optionalString(request.ApiKey),
		ApiSecret:          optionalString(request.ApiSecret),
		Enabled:            request.Enabled,
		Groups:             request.Groups,
		LastSyncedInterval: request.LastSyncedInterval,
		MatchAttributes:    request.MatchAttributes,
	}
}

func fleetDMRequestFromUpdate(request api.EDRFleetDMUpdateRequest) api.EDRFleetDMRequest {
	return api.EDRFleetDMRequest{
		ApiToken:           optionalString(request.ApiToken),
		ApiUrl:             request.ApiUrl,
		Enabled:            request.Enabled,
		Groups:             request.Groups,
		LastSyncedInterval: request.LastSyncedInterval,
		MatchAttributes:    request.MatchAttributes,
	}
}

func optionalString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
