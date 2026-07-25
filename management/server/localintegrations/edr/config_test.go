package edr

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	api "github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/util/crypt"
)

func TestUpdateConfigurationPreservesOmittedSecrets(t *testing.T) {
	previous := &providerConfig{
		APIURL:   "https://sentinel.example.com",
		APIToken: "stored-token",
	}
	request := api.EDRSentinelOneRequest{
		ApiUrl:             "https://sentinel.example.com/",
		Groups:             []string{"group-1"},
		LastSyncedInterval: 24,
		MatchAttributes:    api.SentinelOneMatchAttributes{},
	}
	config, enabled, err := configFromSentinelOne(request, previous)
	require.NoError(t, err)
	require.True(t, enabled)
	require.Equal(t, "stored-token", config.APIToken)
	require.Equal(t, "https://sentinel.example.com", config.APIURL)
}

func TestConfigurationValidationRejectsUnsafeURLsAndBounds(t *testing.T) {
	_, _, err := configFromFleetDM(api.EDRFleetDMRequest{
		ApiUrl:             "http://fleet.example.com",
		ApiToken:           "token",
		LastSyncedInterval: 24,
	}, nil)
	require.ErrorContains(t, err, "HTTPS")

	negative := -1
	_, _, err = configFromFleetDM(api.EDRFleetDMRequest{
		ApiUrl:             "https://fleet.example.com",
		ApiToken:           "token",
		LastSyncedInterval: 24,
		MatchAttributes: api.FleetDMMatchAttributes{
			FailingPoliciesCountMax: &negative,
		},
	}, nil)
	require.ErrorContains(t, err, "must not be negative")

	_, _, err = configFromFalcon(api.EDRFalconRequest{
		ClientId:          "client",
		Secret:            "secret",
		CloudId:           "invalid",
		ZtaScoreThreshold: 50,
	}, nil)
	require.ErrorContains(t, err, "cloud_id")
}

func TestEDRConfigurationIsEncrypted(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	encryptor, err := crypt.NewFieldEncrypt(key)
	require.NoError(t, err)
	encrypted, err := encryptProviderConfig(encryptor, &providerConfig{
		APIURL:   "https://sentinel.example.com",
		APIToken: "plain-secret-token",
	})
	require.NoError(t, err)
	require.NotContains(t, encrypted, "plain-secret-token")

	config, err := decryptProviderConfig(encryptor, encrypted)
	require.NoError(t, err)
	require.Equal(t, "plain-secret-token", config.APIToken)
}
