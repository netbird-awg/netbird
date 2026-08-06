package ldapsync

import (
	"testing"

	"github.com/stretchr/testify/require"

	ldapsyncmodel "github.com/netbirdio/netbird/management/server/localintegrations/ldapsync/model"
)

func TestMergeManagedAutoGroupsPreservesAdministratorAssignments(t *testing.T) {
	merged := mergeManagedAutoGroups(
		[]string{"admin-group", "old-managed"},
		[]string{"name", "email", "auto_group:old-managed"},
		[]string{"new-managed"},
	)

	require.Equal(t, []string{"admin-group", "new-managed"}, merged)
}

func TestConfirmationTokenIsBoundToConfigAndPreview(t *testing.T) {
	service := &Service{syncKey: []byte("01234567890123456789012345678901")}
	config := &ldapsyncmodel.Config{AccountID: "account-a", ConnectorID: "ldap-a", Revision: 7}

	token, _, err := service.issueConfirmationToken(config, "preview-a")
	require.NoError(t, err)
	require.NoError(t, service.validateConfirmationToken(token, config, "preview-a"))

	require.ErrorContains(t, service.validateConfirmationToken(token, config, "preview-b"), "changed")
	tampered := token[:len(token)-1] + "x"
	require.ErrorContains(t, service.validateConfirmationToken(tampered, config, "preview-a"), "invalid")
}

func TestDefaultSyncScopeCannotBeRemovedWithoutExplicitOverride(t *testing.T) {
	service := &Service{}
	request := ConfigRequest{
		Enabled:           true,
		IntervalMinutes:   60,
		SyncScopeGroups:   []string{"engineering"},
		DeprovisionAction: ldapsyncmodel.DeprovisionDisable,
		ConflictPolicy:    ldapsyncmodel.ConflictSkip,
	}

	_, err := service.normalizeConfigRequest(t.Context(), "account-a", request)
	require.ErrorContains(t, err, ldapsyncmodel.DefaultScopeGroup)

	request.AllowWithoutDefaultScope = true
	normalized, err := service.normalizeConfigRequest(t.Context(), "account-a", request)
	require.NoError(t, err)
	require.Equal(t, []string{"engineering"}, normalized.SyncScopeGroups)
}

func TestExternalIDHashIsStableAndTenantScoped(t *testing.T) {
	service := &Service{syncKey: []byte("01234567890123456789012345678901")}

	first := service.externalIDHash("account-a", "ldap-a", "stable-user-id")
	require.Equal(t, first, service.externalIDHash("account-a", "ldap-a", "stable-user-id"))
	require.NotEqual(t, first, service.externalIDHash("account-b", "ldap-a", "stable-user-id"))
	require.NotContains(t, first, "stable-user-id")
}

func TestHighRiskDisableThreshold(t *testing.T) {
	testCases := []struct {
		name          string
		disabled      int
		activeManaged int
		highRisk      bool
	}{
		{name: "below thresholds", disabled: 20, activeManaged: 100, highRisk: false},
		{name: "over percentage", disabled: 21, activeManaged: 100, highRisk: true},
		{name: "over absolute", disabled: 101, activeManaged: 1000, highRisk: true},
		{name: "no managed users", disabled: 0, activeManaged: 0, highRisk: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			highRisk, _ := disableRisk(testCase.disabled, testCase.activeManaged)
			require.Equal(t, testCase.highRisk, highRisk)
		})
	}
}
