package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	scimlib "github.com/elimity-com/scim"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	filter "github.com/scim2/filter-parser/v2"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/account"
	scimmodel "github.com/netbirdio/netbird/management/server/localintegrations/scim/model"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/util/crypt"
)

func TestProtocolUserLifecycleEncryptsPayload(t *testing.T) {
	encryptionKey, err := crypt.GenerateKey()
	require.NoError(t, err)
	encryptor, err := crypt.NewFieldEncrypt(encryptionKey)
	require.NoError(t, err)

	token := "nbs_0123456789012345678901234567890123456789012"
	integration := &scimmodel.Integration{
		ID:        1,
		AccountID: "account",
		Provider:  "generic",
		TokenHash: tokenDigest(token),
		Enabled:   true,
	}
	repository := newMemorySCIMStore(integration)
	service := &Service{
		store:     repository,
		encryptor: encryptor,
		lookupKey: []byte("01234567890123456789012345678901"),
		signal:    make(chan struct{}, 1),
		rateCalls: make(map[string][]time.Time),
	}
	router := mux.NewRouter().PathPrefix("/api").Subrouter()
	require.NoError(t, RegisterProtocolEndpoints(service, router))

	body := `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"externalId":"directory-42",
		"userName":"alice@example.com",
		"displayName":"Alice",
		"active":true,
		"emails":[{"value":"alice@example.com","primary":true}]
	}`
	request := httptest.NewRequest(http.MethodPost, "/api/scim/v2/Users", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())

	var created map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &created))
	resourceID, _ := created["id"].(string)
	require.NotEmpty(t, resourceID)

	stored := repository.resource(resourceID)
	require.NotNil(t, stored)
	require.NotContains(t, stored.EncryptedPayload, "alice@example.com")
	require.NotEmpty(t, stored.UserNameHash)
	require.Equal(t, tokenDigest(token), repository.lastTokenHash)

	query := url.Values{"filter": {`userName eq "alice@example.com"`}}
	request = httptest.NewRequest(http.MethodGet, "/api/scim/v2/Users?"+query.Encode(), nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), resourceID)
	require.Contains(t, response.Body.String(), "alice@example.com")

	request = httptest.NewRequest(http.MethodDelete, "/api/scim/v2/Users/"+resourceID, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusNoContent, response.Code, response.Body.String())

	request = httptest.NewRequest(http.MethodGet, "/api/scim/v2/Users/"+resourceID, nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusNotFound, response.Code, response.Body.String())
}

func TestProtocolRejectsInvalidTokenAndOversizedBody(t *testing.T) {
	integration := &scimmodel.Integration{ID: 1, TokenHash: tokenDigest("nbs_valid"), Enabled: true}
	repository := newMemorySCIMStore(integration)
	service := &Service{
		store:     repository,
		lookupKey: bytes.Repeat([]byte{1}, 32),
		signal:    make(chan struct{}, 1),
		rateCalls: make(map[string][]time.Time),
	}
	router := mux.NewRouter().PathPrefix("/api").Subrouter()
	require.NoError(t, RegisterProtocolEndpoints(service, router))

	request := httptest.NewRequest(http.MethodGet, "/api/scim/v2/Users", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusUnauthorized, response.Code)

	request = httptest.NewRequest(http.MethodPost, "/api/scim/v2/Users", strings.NewReader(strings.Repeat("x", maxSCIMRequestBody+1)))
	request.ContentLength = maxSCIMRequestBody + 1
	request.Header.Set("Authorization", "Bearer nbs_valid")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusRequestEntityTooLarge, response.Code)
}

func TestApplyPatchOperationsUpdatesGroupMembers(t *testing.T) {
	attributes := scimlib.ResourceAttributes{
		"displayName": "Engineering",
		"members":     []any{map[string]any{"value": "user-1"}},
	}
	require.NoError(t, applyPatchOperations(attributes, []scimlib.PatchOperation{
		{
			Op:   scimlib.PatchOperationAdd,
			Path: mustFilterPath(t, "members"),
			Value: []any{
				map[string]any{"value": "user-1"},
				map[string]any{"value": "user-2"},
			},
		},
		{
			Op:   scimlib.PatchOperationRemove,
			Path: mustFilterPath(t, `members[value eq "user-1"]`),
		},
	}))
	require.Equal(t, []any{map[string]any{"value": "user-2"}}, attributes["members"])
}

func TestSyncIntegrationCreatesGroupAndUserMembership(t *testing.T) {
	encryptionKey, err := crypt.GenerateKey()
	require.NoError(t, err)
	encryptor, err := crypt.NewFieldEncrypt(encryptionKey)
	require.NoError(t, err)

	integration := &scimmodel.Integration{
		ID:        7,
		AccountID: "account",
		Provider:  "generic",
		Prefix:    "oidc|employees",
		Enabled:   true,
	}
	repository := newMemorySCIMStore(integration)
	controller := gomock.NewController(t)
	accountManager := account.NewMockManager(controller)
	service := &Service{
		store:     repository,
		accounts:  accountManager,
		encryptor: encryptor,
		lookupKey: []byte("01234567890123456789012345678901"),
		signal:    make(chan struct{}, 1),
	}
	handler := &resourceHandler{service: service, resourceType: scimmodel.ResourceTypeUser}
	now := time.Now().UTC()
	userResource := &scimmodel.Resource{
		ID:            "scim-user-1",
		IntegrationID: integration.ID,
		ResourceType:  scimmodel.ResourceTypeUser,
		CreatedAt:     now,
	}
	require.NoError(t, handler.save(context.Background(), userResource, scimlib.ResourceAttributes{
		"externalId":  "directory-user-1",
		"userName":    "alice@example.com",
		"displayName": "Alice",
		"active":      true,
		"emails":      []any{map[string]any{"value": "alice@example.com", "primary": true}},
	}, now))
	handler.resourceType = scimmodel.ResourceTypeGroup
	groupResource := &scimmodel.Resource{
		ID:            "scim-group-1",
		IntegrationID: integration.ID,
		ResourceType:  scimmodel.ResourceTypeGroup,
		CreatedAt:     now,
	}
	require.NoError(t, handler.save(context.Background(), groupResource, scimlib.ResourceAttributes{
		"externalId":  "directory-group-1",
		"displayName": "Engineering",
		"members":     []any{map[string]any{"value": userResource.ID}},
	}, now))

	var createdGroup *types.Group
	accountManager.EXPECT().
		GetAllGroups(gomock.Any(), integration.AccountID, gomock.Any()).
		Return([]*types.Group{}, nil)
	accountManager.EXPECT().
		CreateGroup(gomock.Any(), integration.AccountID, gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, _, _ string, group *types.Group) error {
			createdGroup = group.Copy()
			return nil
		})
	accountManager.EXPECT().
		ListUsers(gomock.Any(), integration.AccountID).
		Return([]*types.User{}, nil)
	accountManager.EXPECT().
		SaveOrAddUser(gomock.Any(), integration.AccountID, gomock.Any(), gomock.Any(), true).
		DoAndReturn(func(_ context.Context, _, _ string, user *types.User, _ bool) (*types.UserInfo, error) {
			require.NotNil(t, createdGroup)
			require.Equal(t, "oidc|employees|directory-user-1", user.Id)
			require.Equal(t, []string{createdGroup.ID}, user.AutoGroups)
			require.Equal(t, scimmodel.IntegrationType, user.IntegrationReference.IntegrationType)
			return &types.UserInfo{ID: user.Id}, nil
		})

	summary, err := service.syncIntegration(context.Background(), integration)
	require.NoError(t, err)
	require.Equal(t, 1, summary.Groups)
	require.Equal(t, 1, summary.Users)
	require.Zero(t, summary.Skipped)
}

func TestReconcileUsersSkipsEmailCollisionOnUpdate(t *testing.T) {
	integration := &scimmodel.Integration{ID: 7, AccountID: "account", Provider: "generic", Prefix: "oidc"}
	repository := newMemorySCIMStore(integration)
	controller := gomock.NewController(t)
	accountManager := account.NewMockManager(controller)
	service := &Service{store: repository, accounts: accountManager}

	managed := types.NewUser(
		"managed-user", types.UserRoleUser, false, false, "", nil,
		types.UserIssuedIntegration, "old@example.com", "Managed",
	)
	managed.AccountID = integration.AccountID
	reference, err := integrationReference(integration)
	require.NoError(t, err)
	managed.IntegrationReference = reference
	manual := types.NewUser(
		"manual-user", types.UserRoleUser, false, false, "", nil,
		types.UserIssuedAPI, "taken@example.com", "Manual",
	)
	manual.AccountID = integration.AccountID

	accountManager.EXPECT().
		ListUsers(gomock.Any(), integration.AccountID).
		Return([]*types.User{managed, manual}, nil)

	users, disabled, skipped, err := service.reconcileUsers(
		context.Background(),
		integration,
		map[string]*sourceUser{
			"source-user": {
				resource: &scimmodel.Resource{
					ID:              "source-user",
					IntegrationID:   integration.ID,
					ResourceType:    scimmodel.ResourceTypeUser,
					NetBirdObjectID: managed.Id,
				},
				stableID: "directory-user",
				email:    manual.Email,
				name:     "Managed",
				active:   true,
			},
		},
		nil,
		nil,
	)
	require.NoError(t, err)
	require.Zero(t, users)
	require.Zero(t, disabled)
	require.Equal(t, 1, skipped)
}

func TestReconcileGroupsSkipsRenameCollision(t *testing.T) {
	integration := &scimmodel.Integration{ID: 7, AccountID: "account", Provider: "generic"}
	repository := newMemorySCIMStore(integration)
	controller := gomock.NewController(t)
	accountManager := account.NewMockManager(controller)
	service := &Service{store: repository, accounts: accountManager}

	reference, err := integrationReference(integration)
	require.NoError(t, err)
	managed := &types.Group{
		ID:                   "managed-group",
		Name:                 "Old Name",
		Issued:               types.GroupIssuedIntegration,
		IntegrationReference: reference,
	}
	manual := &types.Group{ID: "manual-group", Name: "New Name", Issued: types.GroupIssuedAPI}
	accountManager.EXPECT().
		GetAllGroups(gomock.Any(), integration.AccountID, gomock.Any()).
		Return([]*types.Group{managed, manual}, nil)

	targets, skipped, err := service.reconcileGroups(
		context.Background(),
		integration,
		map[string]*sourceGroup{
			"source-group": {
				resource: &scimmodel.Resource{
					ID:              "source-group",
					IntegrationID:   integration.ID,
					ResourceType:    scimmodel.ResourceTypeGroup,
					NetBirdObjectID: managed.ID,
				},
				name: manual.Name,
			},
		},
	)
	require.NoError(t, err)
	require.Empty(t, targets)
	require.Equal(t, 1, skipped)
}

func TestBuildEligibleUsersAppliesGroupPrefixesOnce(t *testing.T) {
	groups := map[string]*sourceGroup{
		"engineering": {
			resource: &scimmodel.Resource{},
			name:     "sync-engineering",
			members:  []string{"user-1", "user-2"},
		},
		"finance": {
			resource: &scimmodel.Resource{},
			name:     "finance",
			members:  []string{"user-3"},
		},
	}
	require.Equal(t, map[string]struct{}{"user-1": {}, "user-2": {}}, buildEligibleUsers(groups, []string{"sync-"}))
}

func mustFilterPath(t *testing.T, raw string) *filter.Path {
	t.Helper()
	path, err := filter.ParsePath([]byte(raw))
	require.NoError(t, err)
	return &path
}

type memorySCIMStore struct {
	mu            sync.Mutex
	integration   *scimmodel.Integration
	resources     map[string]*scimmodel.Resource
	logs          []*scimmodel.SyncLog
	lastTokenHash string
}

func newMemorySCIMStore(integration *scimmodel.Integration) *memorySCIMStore {
	return &memorySCIMStore{
		integration: integration,
		resources:   make(map[string]*scimmodel.Resource),
	}
}

func (s *memorySCIMStore) resource(id string) *scimmodel.Resource {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resources[id]
}

func (s *memorySCIMStore) GetStoreEngine() types.Engine { return types.PostgresStoreEngine }

func (s *memorySCIMStore) ListSCIMIntegrations(context.Context, string) ([]*scimmodel.Integration, error) {
	return []*scimmodel.Integration{s.integration}, nil
}

func (s *memorySCIMStore) GetSCIMIntegration(context.Context, string, uint64) (*scimmodel.Integration, error) {
	return s.integration, nil
}

func (s *memorySCIMStore) GetSCIMIntegrationByTokenHash(_ context.Context, hash string) (*scimmodel.Integration, error) {
	s.lastTokenHash = hash
	if s.integration.TokenHash != hash {
		return nil, status.Errorf(status.NotFound, "not found")
	}
	return s.integration, nil
}

func (s *memorySCIMStore) CreateSCIMIntegration(context.Context, *scimmodel.Integration) error {
	return nil
}

func (s *memorySCIMStore) UpdateSCIMIntegration(context.Context, *scimmodel.Integration) error {
	return nil
}

func (s *memorySCIMStore) DeleteSCIMIntegration(context.Context, string, uint64) error {
	return nil
}

func (s *memorySCIMStore) RotateSCIMIntegrationToken(context.Context, string, uint64, string, string) error {
	return nil
}

func (s *memorySCIMStore) ListSCIMLogs(context.Context, string, uint64, int) ([]*scimmodel.SyncLog, error) {
	return s.logs, nil
}

func (s *memorySCIMStore) AddSCIMLog(_ context.Context, entry *scimmodel.SyncLog) error {
	s.logs = append(s.logs, entry)
	return nil
}

func (s *memorySCIMStore) GetSCIMResource(_ context.Context, integrationID uint64, resourceType, resourceID string) (*scimmodel.Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	resource := s.resources[resourceID]
	if resource == nil || resource.IntegrationID != integrationID || resource.ResourceType != resourceType || resource.Deleted {
		return nil, status.Errorf(status.NotFound, "not found")
	}
	resourceCopy := *resource
	return &resourceCopy, nil
}

func (s *memorySCIMStore) FindSCIMResources(
	_ context.Context,
	integrationID uint64,
	resourceType, lookupColumn, lookupHash string,
) ([]*scimmodel.Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*scimmodel.Resource
	for _, resource := range s.resources {
		if resource.IntegrationID != integrationID || resource.ResourceType != resourceType || resource.Deleted {
			continue
		}
		if (lookupColumn == "external_id_hash" && resource.ExternalIDHash == lookupHash) ||
			(lookupColumn == "user_name_hash" && resource.UserNameHash == lookupHash) {
			resourceCopy := *resource
			result = append(result, &resourceCopy)
		}
	}
	return result, nil
}

func (s *memorySCIMStore) ListSCIMResources(
	_ context.Context,
	integrationID uint64,
	resourceType string,
	includeDeleted bool,
) ([]*scimmodel.Resource, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*scimmodel.Resource
	for _, resource := range s.resources {
		if resource.IntegrationID != integrationID || resource.ResourceType != resourceType ||
			(resource.Deleted && !includeDeleted) {
			continue
		}
		resourceCopy := *resource
		result = append(result, &resourceCopy)
	}
	return result, nil
}

func (s *memorySCIMStore) SaveSCIMResourceAndQueue(_ context.Context, resource *scimmodel.Resource, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	resourceCopy := *resource
	s.resources[resource.ID] = &resourceCopy
	return nil
}

func (s *memorySCIMStore) DeleteSCIMResourceAndQueue(
	_ context.Context,
	integrationID uint64,
	resourceType, resourceID string,
	_ time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	resource := s.resources[resourceID]
	if resource == nil || resource.IntegrationID != integrationID || resource.ResourceType != resourceType || resource.Deleted {
		return status.Errorf(status.NotFound, "not found")
	}
	resource.Deleted = true
	return nil
}

func (s *memorySCIMStore) UpdateSCIMResourceTarget(
	_ context.Context,
	integrationID uint64,
	resourceType,
	resourceID,
	netBirdObjectID string,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	resource := s.resources[resourceID]
	if resource == nil || resource.IntegrationID != integrationID || resource.ResourceType != resourceType {
		return status.Errorf(status.NotFound, "not found")
	}
	resource.NetBirdObjectID = netBirdObjectID
	return nil
}

//nolint:nilnil // The in-memory store has no background synchronization work.
func (s *memorySCIMStore) ClaimSCIMIntegration(context.Context, time.Time, time.Duration, string) (*scimmodel.Integration, error) {
	return nil, nil
}

func (s *memorySCIMStore) RenewSCIMIntegrationLease(context.Context, uint64, string, time.Time, time.Duration) (bool, error) {
	return true, nil
}

func (s *memorySCIMStore) FinishSCIMIntegrationSync(context.Context, uint64, string, int64, scimmodel.SyncResult) (bool, error) {
	return true, nil
}
