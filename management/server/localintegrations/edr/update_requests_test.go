package edr

import (
	"testing"

	"github.com/stretchr/testify/require"

	api "github.com/netbirdio/netbird/shared/management/http/api"
)

func TestUpdateRequestsPreserveOmittedCredentials(t *testing.T) {
	previous := &providerConfig{
		ClientID:  "stored-client",
		Secret:    "stored-secret",
		APIToken:  "stored-token",
		APIKey:    "stored-key",
		APISecret: "stored-api-secret",
	}

	intune, _, err := configFromIntune(intuneRequestFromUpdate(api.EDRIntuneUpdateRequest{
		ClientId:           "client",
		TenantId:           "tenant",
		Groups:             []string{"group"},
		LastSyncedInterval: 24,
	}), previous)
	require.NoError(t, err)
	require.Equal(t, previous.Secret, intune.Secret)

	falcon, _, err := configFromFalcon(falconRequestFromUpdate(api.EDRFalconUpdateRequest{
		CloudId:           "us-1",
		Groups:            []string{"group"},
		ZtaScoreThreshold: 80,
	}), previous)
	require.NoError(t, err)
	require.Equal(t, previous.ClientID, falcon.ClientID)
	require.Equal(t, previous.Secret, falcon.Secret)

	sentinelOne, _, err := configFromSentinelOne(sentinelOneRequestFromUpdate(api.EDRSentinelOneUpdateRequest{
		ApiUrl:             "https://sentinel.example",
		Groups:             []string{"group"},
		LastSyncedInterval: 24,
	}), previous)
	require.NoError(t, err)
	require.Equal(t, previous.APIToken, sentinelOne.APIToken)

	huntress, _, err := configFromHuntress(huntressRequestFromUpdate(api.EDRHuntressUpdateRequest{
		Groups:             []string{"group"},
		LastSyncedInterval: 24,
	}), previous)
	require.NoError(t, err)
	require.Equal(t, previous.APIKey, huntress.APIKey)
	require.Equal(t, previous.APISecret, huntress.APISecret)

	fleetDM, _, err := configFromFleetDM(fleetDMRequestFromUpdate(api.EDRFleetDMUpdateRequest{
		ApiUrl:             "https://fleet.example",
		Groups:             []string{"group"},
		LastSyncedInterval: 24,
	}), previous)
	require.NoError(t, err)
	require.Equal(t, previous.APIToken, fleetDM.APIToken)
}
