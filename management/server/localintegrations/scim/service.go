package scim

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	scimmodel "github.com/netbirdio/netbird/management/server/localintegrations/scim/model"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	api "github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/util/crypt"
)

const (
	maxPrefixes          = 50
	maxPrefixLength      = 128
	maxSyncLogs          = 100
	scimIntegrationLabel = "SCIM identity provider"
)

var supportedProviders = []string{"generic", "entra", "jumpcloud"}

type scimStore interface {
	GetStoreEngine() types.Engine
	ListSCIMIntegrations(ctx context.Context, accountID string) ([]*scimmodel.Integration, error)
	GetSCIMIntegration(ctx context.Context, accountID string, integrationID uint64) (*scimmodel.Integration, error)
	GetSCIMIntegrationByTokenHash(ctx context.Context, tokenHash string) (*scimmodel.Integration, error)
	CreateSCIMIntegration(ctx context.Context, integration *scimmodel.Integration) error
	UpdateSCIMIntegration(ctx context.Context, integration *scimmodel.Integration) error
	DeleteSCIMIntegration(ctx context.Context, accountID string, integrationID uint64) error
	RotateSCIMIntegrationToken(ctx context.Context, accountID string, integrationID uint64, tokenHash, tokenHint string) error
	ListSCIMLogs(ctx context.Context, accountID string, integrationID uint64, limit int) ([]*scimmodel.SyncLog, error)
	AddSCIMLog(ctx context.Context, log *scimmodel.SyncLog) error
	GetSCIMResource(ctx context.Context, integrationID uint64, resourceType, resourceID string) (*scimmodel.Resource, error)
	FindSCIMResources(ctx context.Context, integrationID uint64, resourceType, lookupColumn, lookupHash string) ([]*scimmodel.Resource, error)
	ListSCIMResources(ctx context.Context, integrationID uint64, resourceType string, includeDeleted bool) ([]*scimmodel.Resource, error)
	SaveSCIMResourceAndQueue(ctx context.Context, resource *scimmodel.Resource, queuedAt time.Time) error
	DeleteSCIMResourceAndQueue(ctx context.Context, integrationID uint64, resourceType, resourceID string, queuedAt time.Time) error
	UpdateSCIMResourceTarget(ctx context.Context, integrationID uint64, resourceType, resourceID, netBirdObjectID string) error
	ClaimSCIMIntegration(ctx context.Context, now time.Time, leaseDuration time.Duration, leaseOwner string) (*scimmodel.Integration, error)
	RenewSCIMIntegrationLease(ctx context.Context, integrationID uint64, leaseOwner string, now time.Time, leaseDuration time.Duration) (bool, error)
	FinishSCIMIntegrationSync(ctx context.Context, integrationID uint64, leaseOwner string, claimedRevision int64, result scimmodel.SyncResult) (bool, error)
}

// Service owns local Generic SCIM configuration, protocol resources, and the
// durable PostgreSQL synchronization worker.
type Service struct {
	store       scimStore
	permissions permissions.Manager
	idpManager  idp.Manager
	accounts    account.Manager
	encryptor   *crypt.FieldEncrypt
	lookupKey   []byte
	metrics     metric.Meter
	workerID    string
	signal      chan struct{}
	startOnce   sync.Once

	rateMu    sync.Mutex
	rateCalls map[string][]time.Time
}

func NewService(
	dataStoreEncryptionKey string,
	dataStore store.Store,
	permissionsManager permissions.Manager,
	idpManager idp.Manager,
	accountManager account.Manager,
	meter metric.Meter,
) (*Service, error) {
	repository, ok := dataStore.(scimStore)
	if !ok {
		return nil, fmt.Errorf("configured NetBird store does not implement local SCIM persistence")
	}
	encryptor, err := crypt.NewFieldEncrypt(dataStoreEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("local SCIM requires a valid DataStoreEncryptionKey: %w", err)
	}
	lookupKey := sha256.Sum256([]byte("netbird/local-scim/lookup/v1\x00" + dataStoreEncryptionKey))
	return &Service{
		store:       repository,
		permissions: permissionsManager,
		idpManager:  idpManager,
		accounts:    accountManager,
		encryptor:   encryptor,
		lookupKey:   lookupKey[:],
		metrics:     meter,
		workerID:    xid.New().String(),
		signal:      make(chan struct{}, 1),
		rateCalls:   make(map[string][]time.Time),
	}, nil
}

func (s *Service) CreateIntegration(
	ctx context.Context,
	accountID, userID string,
	request api.CreateScimIntegrationRequest,
) (*api.ScimIntegration, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Create)
	if err != nil {
		return nil, err
	}
	if err := s.requirePostgres(); err != nil {
		return nil, err
	}
	provider, prefix, connectorID, groupPrefixes, userGroupPrefixes, err := s.normalizeIntegration(
		ctx,
		accountID,
		request.Provider,
		request.Prefix,
		stringValue(request.ConnectorId),
		sliceValue(request.GroupPrefixes),
		sliceValue(request.UserGroupPrefixes),
	)
	if err != nil {
		return nil, err
	}
	plainToken, tokenHash, tokenHint, err := newToken()
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to generate SCIM token")
	}
	integration := &scimmodel.Integration{
		AccountID:         accountID,
		Provider:          provider,
		Prefix:            prefix,
		TokenHash:         tokenHash,
		TokenHint:         tokenHint,
		Enabled:           true,
		GroupPrefixes:     groupPrefixes,
		UserGroupPrefixes: userGroupPrefixes,
		ConnectorID:       connectorID,
	}
	if err := s.store.CreateSCIMIntegration(ctx, integration); err != nil {
		return nil, err
	}
	s.accounts.StoreEvent(ctx, userID, fmt.Sprint(integration.ID), accountID, activity.IntegrationCreated, map[string]any{
		"provider": provider,
		"type":     scimIntegrationLabel,
	})
	response := integrationToAPI(integration)
	response.AuthToken = plainToken
	return response, nil
}

func (s *Service) ListIntegrations(ctx context.Context, accountID, userID string) ([]api.ScimIntegration, error) {
	if _, err := s.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}
	integrations, err := s.store.ListSCIMIntegrations(ctx, accountID)
	if err != nil {
		return nil, err
	}
	result := make([]api.ScimIntegration, 0, len(integrations))
	for _, integration := range integrations {
		result = append(result, *integrationToAPI(integration))
	}
	return result, nil
}

func (s *Service) GetIntegration(ctx context.Context, accountID, userID string, integrationID uint64) (*api.ScimIntegration, error) {
	if _, err := s.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}
	integration, err := s.store.GetSCIMIntegration(ctx, accountID, integrationID)
	if err != nil {
		return nil, err
	}
	return integrationToAPI(integration), nil
}

type UpdateIntegrationRequest struct {
	ConnectorID       *string   `json:"connector_id,omitempty"`
	Enabled           *bool     `json:"enabled,omitempty"`
	GroupPrefixes     *[]string `json:"group_prefixes,omitempty"`
	Prefix            *string   `json:"prefix,omitempty"`
	Provider          *string   `json:"provider,omitempty"`
	UserGroupPrefixes *[]string `json:"user_group_prefixes,omitempty"`
}

func (s *Service) UpdateIntegration(
	ctx context.Context,
	accountID, userID string,
	integrationID uint64,
	request UpdateIntegrationRequest,
) (*api.ScimIntegration, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}
	integration, err := s.store.GetSCIMIntegration(ctx, accountID, integrationID)
	if err != nil {
		return nil, err
	}
	provider := integration.Provider
	if request.Provider != nil {
		provider = *request.Provider
	}
	prefix := integration.Prefix
	if request.Prefix != nil {
		prefix = *request.Prefix
	}
	connectorID := integration.ConnectorID
	if request.ConnectorID != nil {
		connectorID = *request.ConnectorID
	}
	groupPrefixes := integration.GroupPrefixes
	if request.GroupPrefixes != nil {
		groupPrefixes = *request.GroupPrefixes
	}
	userGroupPrefixes := integration.UserGroupPrefixes
	if request.UserGroupPrefixes != nil {
		userGroupPrefixes = *request.UserGroupPrefixes
	}
	provider, prefix, connectorID, groupPrefixes, userGroupPrefixes, err = s.normalizeIntegration(
		ctx, accountID, provider, prefix, connectorID, groupPrefixes, userGroupPrefixes,
	)
	if err != nil {
		return nil, err
	}
	integration.Provider = provider
	integration.Prefix = prefix
	integration.ConnectorID = connectorID
	integration.GroupPrefixes = groupPrefixes
	integration.UserGroupPrefixes = userGroupPrefixes
	if request.Enabled != nil {
		integration.Enabled = *request.Enabled
	}
	if err := s.store.UpdateSCIMIntegration(ctx, integration); err != nil {
		return nil, err
	}
	s.accounts.StoreEvent(ctx, userID, fmt.Sprint(integration.ID), accountID, activity.IntegrationUpdated, map[string]any{
		"provider": provider,
		"type":     scimIntegrationLabel,
		"enabled":  integration.Enabled,
	})
	return integrationToAPI(integration), nil
}

func (s *Service) DeleteIntegration(ctx context.Context, accountID, userID string, integrationID uint64) error {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Delete)
	if err != nil {
		return err
	}
	integration, err := s.store.GetSCIMIntegration(ctx, accountID, integrationID)
	if err != nil {
		return err
	}
	if err := s.store.DeleteSCIMIntegration(ctx, accountID, integrationID); err != nil {
		return err
	}
	s.accounts.StoreEvent(ctx, userID, fmt.Sprint(integrationID), accountID, activity.IntegrationDeleted, map[string]any{
		"provider": integration.Provider,
		"type":     scimIntegrationLabel,
	})
	return nil
}

func (s *Service) RegenerateToken(ctx context.Context, accountID, userID string, integrationID uint64) (*api.ScimTokenResponse, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}
	plainToken, tokenHash, tokenHint, err := newToken()
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to generate SCIM token")
	}
	if err := s.store.RotateSCIMIntegrationToken(ctx, accountID, integrationID, tokenHash, tokenHint); err != nil {
		return nil, err
	}
	s.accounts.StoreEvent(ctx, userID, fmt.Sprint(integrationID), accountID, activity.IntegrationUpdated, map[string]any{
		"type":   scimIntegrationLabel,
		"action": "token_rotated",
	})
	return &api.ScimTokenResponse{AuthToken: plainToken}, nil
}

func (s *Service) ListLogs(ctx context.Context, accountID, userID string, integrationID uint64) ([]api.IdpIntegrationSyncLog, error) {
	if _, err := s.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}
	logs, err := s.store.ListSCIMLogs(ctx, accountID, integrationID, maxSyncLogs)
	if err != nil {
		return nil, err
	}
	result := make([]api.IdpIntegrationSyncLog, 0, len(logs))
	for _, entry := range logs {
		result = append(result, api.IdpIntegrationSyncLog{
			Id:        int64(entry.ID),
			Level:     entry.Level,
			Message:   entry.Message,
			Timestamp: entry.CreatedAt,
		})
	}
	return result, nil
}

func (s *Service) requirePermission(
	ctx context.Context,
	accountID, userID string,
	operation operations.Operation,
) (context.Context, error) {
	ok, permissionCtx, err := s.permissions.ValidateUserPermissions(ctx, accountID, userID, modules.IdentityProviders, operation)
	if err != nil {
		return permissionCtx, status.NewPermissionValidationError(err)
	}
	if !ok {
		return permissionCtx, status.NewPermissionDeniedError()
	}
	return permissionCtx, nil
}

func (s *Service) requirePostgres() error {
	if s.store.GetStoreEngine() != types.PostgresStoreEngine {
		return status.Errorf(status.PreconditionFailed, "local SCIM synchronization requires PostgreSQL")
	}
	return nil
}

func (s *Service) normalizeIntegration(
	ctx context.Context,
	accountID, provider, prefix, connectorID string,
	groupPrefixes, userGroupPrefixes []string,
) (string, string, string, []string, []string, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if !slices.Contains(supportedProviders, provider) {
		return "", "", "", nil, nil, status.Errorf(status.InvalidArgument, "provider must be generic, entra, or jumpcloud")
	}
	prefix = strings.TrimSpace(prefix)
	if len(prefix) > 255 {
		return "", "", "", nil, nil, status.Errorf(status.InvalidArgument, "prefix is too long")
	}
	connectorID = strings.TrimSpace(connectorID)
	if len(connectorID) > 255 {
		return "", "", "", nil, nil, status.Errorf(status.InvalidArgument, "connector_id is too long")
	}
	if connectorID != "" {
		if err := s.validateConnector(ctx, accountID, connectorID); err != nil {
			return "", "", "", nil, nil, err
		}
	}
	if connectorID == "" && prefix == "" {
		return "", "", "", nil, nil, status.Errorf(
			status.InvalidArgument,
			"connector_id or prefix is required to map SCIM users to login identities",
		)
	}
	groupPrefixes, err := normalizePrefixes(groupPrefixes)
	if err != nil {
		return "", "", "", nil, nil, err
	}
	userGroupPrefixes, err = normalizePrefixes(userGroupPrefixes)
	if err != nil {
		return "", "", "", nil, nil, err
	}
	return provider, prefix, connectorID, groupPrefixes, userGroupPrefixes, nil
}

func (s *Service) validateConnector(ctx context.Context, accountID, connectorID string) error {
	embedded, ok := s.idpManager.(*idp.EmbeddedIdPManager)
	if !ok || embedded == nil {
		return status.Errorf(status.PreconditionFailed, "connector_id requires the embedded identity provider")
	}
	connector, err := embedded.GetConnector(ctx, connectorID)
	if err != nil || connector == nil || (connector.AccountID != "" && connector.AccountID != accountID) {
		return status.Errorf(status.NotFound, "identity provider connector not found")
	}
	return nil
}

func normalizePrefixes(values []string) ([]string, error) {
	if len(values) > maxPrefixes {
		return nil, status.Errorf(status.InvalidArgument, "at most %d prefixes are allowed", maxPrefixes)
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if len(value) > maxPrefixLength {
			return nil, status.Errorf(status.InvalidArgument, "prefix is too long")
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}

func integrationToAPI(integration *scimmodel.Integration) *api.ScimIntegration {
	lastSyncedAt := time.Time{}
	if integration.LastSyncedAt != nil {
		lastSyncedAt = *integration.LastSyncedAt
	}
	var connectorID *string
	if integration.ConnectorID != "" {
		value := integration.ConnectorID
		connectorID = &value
	}
	return &api.ScimIntegration{
		AuthToken:         maskedToken(integration.TokenHint),
		ConnectorId:       connectorID,
		Enabled:           integration.Enabled,
		GroupPrefixes:     append([]string(nil), integration.GroupPrefixes...),
		Id:                int64(integration.ID),
		LastSyncedAt:      lastSyncedAt,
		Prefix:            integration.Prefix,
		Provider:          integration.Provider,
		UserGroupPrefixes: append([]string(nil), integration.UserGroupPrefixes...),
	}
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func sliceValue(value *[]string) []string {
	if value == nil {
		return nil
	}
	return *value
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var statusErr *status.Error
	return errors.As(err, &statusErr) && statusErr.Type() == status.NotFound
}
