package accounts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func TestUpdateAccountRequestSettingsMapsTunnelConfiguration(t *testing.T) {
	policy := api.AccountSettingsTunnelPolicyPreferAwg
	action := api.AccountSettingsTunnelProfileActionActivate
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
			TunnelProfileAction: &action,
		},
	}

	settings, err := (&handler{}).updateAccountRequestSettings(request)
	require.NoError(t, err)
	require.Equal(t, types.TunnelAccountPolicyPreferAWG, settings.TunnelPolicy)
	require.NotNil(t, settings.TunnelProfile)
	require.Equal(t, "awg2", settings.TunnelProfile.ProtocolVersion)
	require.Equal(t, uint64(7), settings.TunnelProfile.Revision)
	require.Equal(
		t,
		types.TunnelProfileActionActivate,
		settings.TunnelProfileAction,
	)

	var parameters map[string]interface{}
	require.NoError(t, json.Unmarshal(settings.TunnelProfile.Parameters, &parameters))
	require.Equal(t, float64(4), parameters["junk_packet_count"])
}

func TestToAccountResponseMapsTunnelConfiguration(t *testing.T) {
	graceUntil := time.Date(2026, time.August, 8, 1, 2, 3, 0, time.UTC)
	response := toAccountResponse(
		"account",
		&types.Settings{
			TunnelPolicy: types.TunnelAccountPolicyRequireAWG,
			TunnelProfile: &types.TunnelProfile{
				ProtocolVersion: "awg2",
				Revision:        3,
				Parameters:      json.RawMessage(`{"junk_packet_count":4}`),
			},
			TunnelProfilePending: &types.TunnelProfile{
				ProtocolVersion: "awg3",
				Revision:        4,
				Parameters: json.RawMessage(
					`{"content_padding_addition":"1-8"}`,
				),
			},
			TunnelProfileGraceUntil: graceUntil,
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
	require.NotNil(t, response.Settings.PendingTunnelProfile)
	require.Equal(
		t,
		uint64(4),
		response.Settings.PendingTunnelProfile.Revision,
	)
	require.NotNil(t, response.Settings.TunnelProfileGraceUntil)
	require.Equal(t, graceUntil, *response.Settings.TunnelProfileGraceUntil)
}

func TestToAccountResponseDoesNotExposeAWG3HeaderKey(t *testing.T) {
	response := toAccountResponse(
		"account",
		&types.Settings{
			TunnelProfile: &types.TunnelProfile{
				ProtocolVersion:     "awg3",
				Revision:            4,
				Parameters:          json.RawMessage(`{"content_padding_addition":"1-16"}`),
				HeaderProtectionKey: bytes.Repeat([]byte{0x5a}, 32),
			},
			TunnelProfilePending: &types.TunnelProfile{
				ProtocolVersion:     "awg3",
				Revision:            5,
				Parameters:          json.RawMessage(`{"content_padding_addition":"1-8"}`),
				HeaderProtectionKey: bytes.Repeat([]byte{0x6b}, 32),
			},
		},
		&types.AccountMeta{},
		&types.AccountOnboarding{},
	)

	require.NotNil(t, response.Settings.TunnelProfile)
	encoded, err := json.Marshal(response.Settings.TunnelProfile)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "header_protection")
	require.NotContains(
		t,
		string(encoded),
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32)),
	)
	require.NotContains(
		t,
		string(encoded),
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x6b}, 32)),
	)
}
