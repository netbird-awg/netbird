package accounts

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func TestUpdateAccountRequestSettingsMapsTunnelConfiguration(t *testing.T) {
	policy := api.AccountSettingsTunnelPolicyPreferAwg
	request := api.PutApiAccountsAccountIdJSONRequestBody{
		Settings: api.AccountSettings{
			TunnelPolicy: &policy,
			TunnelProfile: &api.TunnelProfile{
				ProtocolVersion: api.TunnelProfileProtocolVersionAwg2,
				Revision:        7,
				Parameters: map[string]interface{}{
					"junk_packet_count": float64(4),
				},
			},
		},
	}

	settings, err := (&handler{}).updateAccountRequestSettings(request)
	require.NoError(t, err)
	require.Equal(t, types.TunnelAccountPolicyPreferAWG, settings.TunnelPolicy)
	require.NotNil(t, settings.TunnelProfile)
	require.Equal(t, "awg2", settings.TunnelProfile.ProtocolVersion)
	require.Equal(t, uint64(7), settings.TunnelProfile.Revision)

	var parameters map[string]interface{}
	require.NoError(t, json.Unmarshal(settings.TunnelProfile.Parameters, &parameters))
	require.Equal(t, float64(4), parameters["junk_packet_count"])
}

func TestToAccountResponseMapsTunnelConfiguration(t *testing.T) {
	response := toAccountResponse(
		"account",
		&types.Settings{
			TunnelPolicy: types.TunnelAccountPolicyRequireAWG,
			TunnelProfile: &types.TunnelProfile{
				ProtocolVersion: "awg2",
				Revision:        3,
				Parameters:      json.RawMessage(`{"junk_packet_count":4}`),
			},
		},
		&types.AccountMeta{},
		&types.AccountOnboarding{},
	)

	require.NotNil(t, response.Settings.TunnelPolicy)
	require.Equal(
		t,
		api.AccountSettingsTunnelPolicyRequireAwg,
		*response.Settings.TunnelPolicy,
	)
	require.NotNil(t, response.Settings.TunnelProfile)
	require.Equal(t, uint64(3), response.Settings.TunnelProfile.Revision)
	require.Equal(
		t,
		float64(4),
		response.Settings.TunnelProfile.Parameters["junk_packet_count"],
	)
}
