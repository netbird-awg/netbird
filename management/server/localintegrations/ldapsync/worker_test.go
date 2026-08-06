package ldapsync

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	ldapsyncmodel "github.com/netbirdio/netbird/management/server/localintegrations/ldapsync/model"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestFailRunPausesNonRetryableConfigurationErrors(t *testing.T) {
	controller := gomock.NewController(t)
	dataStore := store.NewMockStore(controller)
	service := &Service{store: dataStore}
	run := &ldapsyncmodel.Run{ID: "run-a", AccountID: "account-a", ConnectorID: "ldap-a"}
	config := &ldapsyncmodel.Config{ID: 1, Enabled: true, FailureCount: 0}

	dataStore.EXPECT().UpdateLDAPSyncRun(gomock.Any(), run).Return(nil)
	dataStore.EXPECT().UpdateLDAPSyncConfigRuntime(gomock.Any(), config).DoAndReturn(func(_ context.Context, updated *ldapsyncmodel.Config) error {
		require.Equal(t, "configuration_error", updated.PausedReason)
		require.Nil(t, updated.NextRunAt)
		return nil
	})

	service.failRun(t.Context(), run, config, "ldap_source_unavailable", "LDAP bind failed", false)
	require.Equal(t, ldapsyncmodel.RunStatusFailed, run.Status)
	require.Equal(t, 1, config.FailureCount)
}

func TestFailRunRetriesNetworkErrorsWithBackoff(t *testing.T) {
	controller := gomock.NewController(t)
	dataStore := store.NewMockStore(controller)
	service := &Service{store: dataStore}
	run := &ldapsyncmodel.Run{ID: "run-a", AccountID: "account-a", ConnectorID: "ldap-a"}
	config := &ldapsyncmodel.Config{ID: 1, Enabled: true, FailureCount: 0}

	dataStore.EXPECT().UpdateLDAPSyncRun(gomock.Any(), run).Return(nil)
	dataStore.EXPECT().UpdateLDAPSyncConfigRuntime(gomock.Any(), config).DoAndReturn(func(_ context.Context, updated *ldapsyncmodel.Config) error {
		require.Empty(t, updated.PausedReason)
		require.NotNil(t, updated.NextRunAt)
		require.WithinDuration(t, time.Now().UTC().Add(5*time.Minute), *updated.NextRunAt, 2*time.Second)
		return nil
	})

	service.failRun(t.Context(), run, config, "ldap_source_unavailable", "LDAP connection failed", true)
}

func TestApplyUnchangedActionRefreshesManagedObjectOnly(t *testing.T) {
	controller := gomock.NewController(t)
	dataStore := store.NewMockStore(controller)
	service := &Service{store: dataStore}
	config := &ldapsyncmodel.Config{ID: 1, AccountID: "account-a", ConnectorID: "ldap-a"}
	object := &ldapsyncmodel.Object{
		AccountID:   config.AccountID,
		ConnectorID: config.ConnectorID,
		ObjectType:  ldapsyncmodel.ObjectTypeUser,
		ExternalID:  "external-hmac",
	}
	action := &planAction{
		kind:              "unchanged",
		source:            &dex.LDAPDirectoryUser{StableID: "source-a", Email: "user@example.org", Name: "User", Groups: []string{"netbird"}},
		user:              &types.User{Id: "user-a"},
		object:            object,
		desiredAutoGroups: []string{"group-a"},
		managedFields:     []string{"name", "email", "auto_group:group-a"},
	}

	dataStore.EXPECT().SaveLDAPSyncObjects(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, objects []*ldapsyncmodel.Object) error {
			require.Len(t, objects, 1)
			require.Equal(t, object, objects[0])
			require.Equal(t, "user-a", objects[0].NetBirdObjectID)
			require.Equal(t, ldapsyncmodel.ObjectStatusActive, objects[0].Status)
			require.NotEmpty(t, objects[0].SourceFingerprint)
			require.False(t, objects[0].LastSeenAt.IsZero())
			return nil
		},
	)

	require.NoError(t, service.applyAction(t.Context(), config, action))
}

func TestApplyUpdateUsesAccountManagerSideEffects(t *testing.T) {
	controller := gomock.NewController(t)
	dataStore := store.NewMockStore(controller)
	accountManager := account.NewMockManager(controller)
	service := &Service{store: dataStore, events: accountManager}
	config := &ldapsyncmodel.Config{ID: 1, AccountID: "account-a", ConnectorID: "ldap-a"}
	object := &ldapsyncmodel.Object{
		AccountID:   config.AccountID,
		ConnectorID: config.ConnectorID,
		ObjectType:  ldapsyncmodel.ObjectTypeUser,
		ExternalID:  "external-hmac",
	}
	action := &planAction{
		kind:              "update",
		source:            &dex.LDAPDirectoryUser{StableID: "source-a", Email: "new@example.org", Name: "New Name", Groups: []string{"netbird"}},
		user:              &types.User{Id: "user-a", AccountID: config.AccountID, Email: "old@example.org", Name: "Old Name", AutoGroups: []string{"old-group"}},
		object:            object,
		desiredAutoGroups: []string{"new-group"},
		managedFields:     []string{"name", "email", "auto_group:new-group"},
	}

	accountManager.EXPECT().SaveUser(gomock.Any(), config.AccountID, activity.SystemInitiator, gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _ string, user *types.User) (*types.UserInfo, error) {
			require.Equal(t, "new@example.org", user.Email)
			require.Equal(t, "New Name", user.Name)
			require.Equal(t, []string{"new-group"}, user.AutoGroups)
			return &types.UserInfo{ID: user.Id}, nil
		},
	)
	dataStore.EXPECT().SaveLDAPSyncObjects(gomock.Any(), gomock.Any()).Return(nil)

	require.NoError(t, service.applyAction(t.Context(), config, action))
	require.Equal(t, "old@example.org", action.user.Email, "planner snapshot must not be mutated")
}

func TestApplyUpdatePreservesAdministratorBlock(t *testing.T) {
	controller := gomock.NewController(t)
	dataStore := store.NewMockStore(controller)
	accountManager := account.NewMockManager(controller)
	service := &Service{store: dataStore, events: accountManager}
	config := &ldapsyncmodel.Config{ID: 1, AccountID: "account-a", ConnectorID: "ldap-a"}
	action := &planAction{
		kind:   "update",
		source: &dex.LDAPDirectoryUser{StableID: "source-a", Email: "new@example.org", Name: "New Name"},
		user: &types.User{
			Id: "user-a", AccountID: config.AccountID, Blocked: true, LDAPSyncBlocked: false,
		},
		object: &ldapsyncmodel.Object{
			AccountID: config.AccountID, ConnectorID: config.ConnectorID, ObjectType: ldapsyncmodel.ObjectTypeUser, ExternalID: "external-hmac",
		},
	}

	accountManager.EXPECT().SaveUser(gomock.Any(), config.AccountID, activity.SystemInitiator, gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _ string, user *types.User) (*types.UserInfo, error) {
			require.True(t, user.Blocked)
			require.False(t, user.LDAPSyncBlocked)
			return &types.UserInfo{ID: user.Id}, nil
		},
	)
	dataStore.EXPECT().SaveLDAPSyncObjects(gomock.Any(), gomock.Any()).Return(nil)

	require.NoError(t, service.applyAction(t.Context(), config, action))
}

func TestApplyUpdateOnlyClearsLDAPSyncOwnedBlock(t *testing.T) {
	controller := gomock.NewController(t)
	dataStore := store.NewMockStore(controller)
	accountManager := account.NewMockManager(controller)
	service := &Service{store: dataStore, events: accountManager}
	config := &ldapsyncmodel.Config{ID: 1, AccountID: "account-a", ConnectorID: "ldap-a"}
	action := &planAction{
		kind:   "update",
		source: &dex.LDAPDirectoryUser{StableID: "source-a", Email: "user@example.org", Name: "User"},
		user: &types.User{
			Id: "user-a", AccountID: config.AccountID, Blocked: true, LDAPSyncBlocked: true,
		},
		object: &ldapsyncmodel.Object{
			AccountID: config.AccountID, ConnectorID: config.ConnectorID, ObjectType: ldapsyncmodel.ObjectTypeUser, ExternalID: "external-hmac",
		},
	}

	accountManager.EXPECT().SaveUser(gomock.Any(), config.AccountID, activity.SystemInitiator, gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _ string, user *types.User) (*types.UserInfo, error) {
			require.False(t, user.Blocked)
			require.False(t, user.LDAPSyncBlocked)
			return &types.UserInfo{ID: user.Id}, nil
		},
	)
	dataStore.EXPECT().SaveLDAPSyncObjects(gomock.Any(), gomock.Any()).Return(nil)

	require.NoError(t, service.applyAction(t.Context(), config, action))
}
