package eventstreaming

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/activity"
	eventmodel "github.com/netbirdio/netbird/management/server/localintegrations/eventstreaming/model"
	"github.com/netbirdio/netbird/management/server/outbound"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	api "github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/util/crypt"
)

type sqlStore interface {
	GetDB() *gorm.DB
	GetStoreEngine() types.Engine
}

// StreamEvent is the stable payload shared by every local event destination.
type StreamEvent struct {
	ID          uint64         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	Code        string         `json:"code"`
	Message     string         `json:"message"`
	InitiatorID string         `json:"initiator_id"`
	TargetID    string         `json:"target_id"`
	AccountID   string         `json:"account_id"`
	Meta        map[string]any `json:"meta,omitempty"`
}

// Service decorates the existing activity store and adds a PostgreSQL-backed
// outbox without changing the upstream activity.Store contract.
type Service struct {
	next        activity.Store
	repository  *repository
	permissions permissions.Manager
	encryptor   *crypt.FieldEncrypt
	validator   *outbound.Validator
	httpClient  httpDoer
	workerID    string
	signal      chan struct{}
	startOnce   sync.Once
}

func NewService(
	next activity.Store,
	dataStore store.Store,
	permissionsManager permissions.Manager,
	dataStoreEncryptionKey string,
) (*Service, error) {
	if next == nil {
		return nil, fmt.Errorf("activity store is required")
	}
	sql, ok := dataStore.(sqlStore)
	if !ok || sql.GetStoreEngine() != types.PostgresStoreEngine {
		return nil, fmt.Errorf("local event streaming requires PostgreSQL")
	}
	encryptor, err := crypt.NewFieldEncrypt(dataStoreEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("local event streaming requires a valid DataStoreEncryptionKey: %w", err)
	}
	validator, err := outbound.NewValidatorFromEnv()
	if err != nil {
		return nil, fmt.Errorf("configure local event streaming outbound policy: %w", err)
	}
	client := validator.HTTPClient()
	repository := &repository{db: sql.GetDB()}
	constraintCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := repository.ensureConstraints(constraintCtx); err != nil {
		return nil, fmt.Errorf("initialize local event streaming constraints: %w", err)
	}
	return &Service{
		next:        next,
		repository:  repository,
		permissions: permissionsManager,
		encryptor:   encryptor,
		validator:   validator,
		httpClient:  client,
		workerID:    xid.New().String(),
		signal:      make(chan struct{}, 1),
	}, nil
}

func (s *Service) Save(ctx context.Context, event *activity.Event) (*activity.Event, error) {
	saved, err := s.next.Save(ctx, event)
	if err != nil {
		return nil, err
	}
	streamEvent := StreamEvent{
		ID:          saved.ID,
		Timestamp:   saved.Timestamp,
		Code:        saved.Activity.StringCode(),
		Message:     saved.Activity.Message(),
		InitiatorID: saved.InitiatorID,
		TargetID:    saved.TargetID,
		AccountID:   saved.AccountID,
		Meta:        saved.Meta,
	}
	payload, err := json.Marshal(streamEvent)
	if err != nil {
		return saved, fmt.Errorf("marshal event stream payload: %w", err)
	}
	if len(payload) > maxRenderedBody {
		return saved, fmt.Errorf("event stream payload exceeds %d bytes", maxRenderedBody)
	}
	encrypted, err := s.encryptor.Encrypt(string(payload))
	if err != nil {
		return saved, fmt.Errorf("encrypt event stream payload: %w", err)
	}
	queueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	queued, err := s.repository.enqueue(queueCtx, saved.AccountID, saved.ID, encrypted)
	if err != nil {
		return saved, err
	}
	if queued {
		s.notifyWorker()
	}
	return saved, nil
}

func (s *Service) Get(
	ctx context.Context,
	accountID string,
	offset, limit int,
	descending bool,
) ([]*activity.Event, error) {
	return s.next.Get(ctx, accountID, offset, limit, descending)
}

func (s *Service) Close(ctx context.Context) error {
	return s.next.Close(ctx)
}

func (s *Service) CreateIntegration(
	ctx context.Context,
	accountID, userID string,
	request api.CreateIntegrationRequest,
) (*api.IntegrationResponse, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Create)
	if err != nil {
		return nil, err
	}
	platform := string(request.Platform)
	config, err := normalizeConfig(ctx, s.validator, platform, request.Config, nil)
	if err != nil {
		return nil, err
	}
	encrypted, err := s.encryptConfig(config)
	if err != nil {
		return nil, err
	}
	integration := &eventmodel.Integration{
		AccountID:       accountID,
		Platform:        platform,
		Enabled:         request.Enabled,
		EncryptedConfig: encrypted,
	}
	if err := s.repository.create(ctx, integration); err != nil {
		return nil, err
	}
	s.audit(ctx, userID, accountID, integration, activity.IntegrationCreated)
	return s.integrationResponse(integration)
}

func (s *Service) ListIntegrations(
	ctx context.Context,
	accountID, userID string,
) ([]api.IntegrationResponse, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Read)
	if err != nil {
		return nil, err
	}
	integrations, err := s.repository.list(ctx, accountID)
	if err != nil {
		return nil, err
	}
	result := make([]api.IntegrationResponse, 0, len(integrations))
	for _, integration := range integrations {
		response, err := s.integrationResponse(integration)
		if err != nil {
			return nil, err
		}
		result = append(result, *response)
	}
	return result, nil
}

func (s *Service) GetIntegration(
	ctx context.Context,
	accountID, userID string,
	id uint64,
) (*api.IntegrationResponse, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Read)
	if err != nil {
		return nil, err
	}
	integration, err := s.repository.get(ctx, accountID, id)
	if err != nil {
		return nil, err
	}
	return s.integrationResponse(integration)
}

func (s *Service) UpdateIntegration(
	ctx context.Context,
	accountID, userID string,
	id uint64,
	request api.CreateIntegrationRequest,
) (*api.IntegrationResponse, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}
	integration, err := s.repository.get(ctx, accountID, id)
	if err != nil {
		return nil, err
	}
	previous, err := s.decryptConfig(integration.EncryptedConfig)
	if err != nil {
		return nil, err
	}
	if request.Config == nil {
		request.Config = make(map[string]string)
	}
	if integration.Platform == "generic_http" {
		headers, err := mergeMaskedHeaders(previous["headers"], request.Config["headers"])
		if err != nil {
			return nil, status.Errorf(status.InvalidArgument, "invalid HTTP headers")
		}
		request.Config["headers"] = headers
	}
	config, err := normalizeConfig(ctx, s.validator, integration.Platform, request.Config, previous)
	if err != nil {
		return nil, err
	}
	encrypted, err := s.encryptConfig(config)
	if err != nil {
		return nil, err
	}
	integration.Enabled = request.Enabled
	integration.EncryptedConfig = encrypted
	if err := s.repository.update(ctx, integration); err != nil {
		return nil, err
	}
	integration.UpdatedAt = time.Now().UTC()
	s.audit(ctx, userID, accountID, integration, activity.IntegrationUpdated)
	return s.integrationResponse(integration)
}

func (s *Service) DeleteIntegration(
	ctx context.Context,
	accountID, userID string,
	id uint64,
) error {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Delete)
	if err != nil {
		return err
	}
	integration, err := s.repository.get(ctx, accountID, id)
	if err != nil {
		return err
	}
	if err := s.repository.delete(ctx, accountID, id); err != nil {
		return err
	}
	s.audit(ctx, userID, accountID, integration, activity.IntegrationDeleted)
	return nil
}

func (s *Service) requirePermission(
	ctx context.Context,
	accountID, userID string,
	operation operations.Operation,
) (context.Context, error) {
	ok, permissionCtx, err := s.permissions.ValidateUserPermissions(
		ctx, accountID, userID, modules.EventStreaming, operation,
	)
	if err != nil {
		return permissionCtx, status.NewPermissionValidationError(err)
	}
	if !ok {
		return permissionCtx, status.NewPermissionDeniedError()
	}
	return permissionCtx, nil
}

func (s *Service) integrationResponse(
	integration *eventmodel.Integration,
) (*api.IntegrationResponse, error) {
	config, err := s.decryptConfig(integration.EncryptedConfig)
	if err != nil {
		return nil, err
	}
	if integration.ID > math.MaxInt64 {
		return nil, status.Errorf(status.Internal, "event streaming integration id is out of range")
	}
	id := int64(integration.ID)
	platform := api.IntegrationResponsePlatform(integration.Platform)
	return &api.IntegrationResponse{
		Id:        &id,
		AccountId: &integration.AccountID,
		Enabled:   &integration.Enabled,
		Platform:  &platform,
		Config:    pointer(maskConfig(config)),
		CreatedAt: &integration.CreatedAt,
		UpdatedAt: &integration.UpdatedAt,
	}, nil
}

func (s *Service) encryptConfig(config map[string]string) (string, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return "", status.Errorf(status.Internal, "failed to encode event streaming configuration")
	}
	encrypted, err := s.encryptor.Encrypt(string(data))
	if err != nil {
		return "", status.Errorf(status.Internal, "failed to encrypt event streaming configuration")
	}
	return encrypted, nil
}

func (s *Service) decryptConfig(encrypted string) (map[string]string, error) {
	plain, err := s.encryptor.Decrypt(encrypted)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to decrypt event streaming configuration")
	}
	var config map[string]string
	if err := json.Unmarshal([]byte(plain), &config); err != nil {
		return nil, status.Errorf(status.Internal, "invalid stored event streaming configuration")
	}
	return config, nil
}

func (s *Service) audit(
	ctx context.Context,
	userID, accountID string,
	integration *eventmodel.Integration,
	code activity.Activity,
) {
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_, err := s.Save(auditCtx, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    code,
		InitiatorID: userID,
		TargetID:    fmt.Sprint(integration.ID),
		AccountID:   accountID,
		Meta: map[string]any{
			"type":     "event_streaming",
			"platform": integration.Platform,
		},
	})
	if err != nil {
		log.WithContext(ctx).WithError(err).Warn("failed to store event streaming audit event")
	}
}

func (s *Service) notifyWorker() {
	select {
	case s.signal <- struct{}{}:
	default:
	}
}

func pointer[T any](value T) *T {
	return &value
}
