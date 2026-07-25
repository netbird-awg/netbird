package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestMFAPolicyServiceLocalPolicies(t *testing.T) {
	tests := []struct {
		name           string
		policy         types.MFAPolicy
		accountDefault bool
		expected       bool
	}{
		{name: "required overrides disabled account", policy: types.MFAPolicyRequired, expected: true},
		{name: "disabled overrides enabled account", policy: types.MFAPolicyDisabled, accountDefault: true, expected: false},
		{name: "inherit enabled account", policy: types.MFAPolicyInherit, accountDefault: true, expected: true},
		{name: "legacy empty policy inherits", policy: "", accountDefault: false, expected: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			dataStore := store.NewMockStore(ctrl)
			encodedUserID := dex.EncodeDexUserID("raw-user", "local")
			dataStore.EXPECT().GetUserByUserID(gomock.Any(), store.LockingStrengthNone, encodedUserID).Return(&types.User{
				Id:        encodedUserID,
				AccountID: "account-1",
				MFAPolicy: test.policy,
			}, nil)
			if test.policy.Normalized() == types.MFAPolicyInherit {
				dataStore.EXPECT().GetAccountSettings(gomock.Any(), store.LockingStrengthNone, "account-1").Return(&types.Settings{
					LocalMfaEnabled: test.accountDefault,
				}, nil)
			}

			service := newMFAPolicyService(dataStore, nil)
			required, err := service.Requirement(context.Background(), "raw-user", "local")
			require.NoError(t, err)
			assert.Equal(t, test.expected, required)
		})
	}
}

func TestMFAPolicyServiceLDAPUserOverride(t *testing.T) {
	ctx := context.Background()
	manager, err := idp.NewEmbeddedIdPManager(ctx, &idp.EmbeddedIdPConfig{
		Enabled: true,
		Issuer:  "http://localhost:5556/oauth2",
		Storage: idp.EmbeddedStorageConfig{
			Type: "sqlite3",
			Config: idp.EmbeddedStorageTypeConfig{
				File: filepath.Join(t.TempDir(), "idp.db"),
			},
		},
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Stop(ctx)) })

	_, err = manager.CreateConnector(ctx, &dex.ConnectorConfig{
		ID:   "ldap-main",
		Name: "LDAP",
		Type: "ldap",
		LDAP: &dex.LDAPConnectorConfig{
			Host:                "ldap.example.test:389",
			InsecureNoSSL:       true,
			UserSearchBaseDN:    "ou=users,dc=example,dc=test",
			UserSearchUsername:  "uid",
			UserSearchIDAttr:    "uid",
			UserSearchEmailAttr: "mail",
			UserSearchNameAttr:  "cn",
		},
	})
	require.NoError(t, err)

	ctrl := gomock.NewController(t)
	dataStore := store.NewMockStore(ctrl)
	encodedUserID := dex.EncodeDexUserID("ldap-user", "ldap-main")
	dataStore.EXPECT().GetUserByUserID(gomock.Any(), store.LockingStrengthNone, encodedUserID).Return(&types.User{
		Id:        encodedUserID,
		AccountID: "account-1",
		MFAPolicy: types.MFAPolicyRequired,
	}, nil)

	service := newMFAPolicyService(dataStore, manager)
	required, err := service.Requirement(ctx, "ldap-user", "ldap-main")
	require.NoError(t, err)
	assert.True(t, required)

	_, err = manager.CreateConnector(ctx, &dex.ConnectorConfig{
		ID:           "google-main",
		Name:         "Google",
		Type:         "google",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	})
	require.NoError(t, err)
	required, err = service.Requirement(ctx, "external-user", "google-main")
	require.NoError(t, err)
	assert.False(t, required, "external OIDC providers keep their own MFA policy")
}

func TestMFAPolicyServiceAllowsFirstLoginBeforeUserProvisioning(t *testing.T) {
	ctrl := gomock.NewController(t)
	dataStore := store.NewMockStore(ctrl)
	encodedUserID := dex.EncodeDexUserID("new-user", "local")
	dataStore.EXPECT().GetUserByUserID(gomock.Any(), store.LockingStrengthNone, encodedUserID).
		Return(nil, status.NewUserNotFoundError(encodedUserID))

	service := newMFAPolicyService(dataStore, nil)
	required, err := service.Requirement(context.Background(), "new-user", "local")
	require.NoError(t, err)
	assert.False(t, required)
}

func TestMFAPolicyServicePersistsLockoutWithoutRedis(t *testing.T) {
	ctx := context.Background()
	dataStore, err := store.NewSqliteStore(ctx, t.TempDir(), nil, false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, dataStore.Close(ctx)) })

	rawUserID := "local-user"
	encodedUserID := dex.EncodeDexUserID(rawUserID, "local")
	require.NoError(t, dataStore.SaveUser(ctx, &types.User{
		Id:        encodedUserID,
		AccountID: "account-1",
		Role:      types.UserRoleUser,
		MFAPolicy: types.MFAPolicyRequired,
	}))

	now := time.Date(2026, time.July, 16, 0, 0, 0, 0, time.UTC)
	service := newMFAPolicyService(dataStore, nil)
	service.now = func() time.Time { return now }

	for range maxNativeMFAFailures {
		require.NoError(t, service.RecordFailure(ctx, rawUserID, "local"))
	}
	retryAfter, err := service.Check(ctx, rawUserID, "local")
	require.NoError(t, err)
	assert.Equal(t, nativeMFALockout, retryAfter)

	require.NoError(t, service.Clear(ctx, rawUserID, "local"))
	retryAfter, err = service.Check(ctx, rawUserID, "local")
	require.NoError(t, err)
	assert.Zero(t, retryAfter)
}
