package edr

import (
	"context"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/management/server/activity"
	edrmodel "github.com/netbirdio/netbird/management/server/localintegrations/edr/model"
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

const (
	defaultSyncInterval             = 5 * time.Minute
	defaultCacheMaxAge              = 30 * time.Minute
	defaultSyncTimeout              = 5 * time.Minute
	defaultFleetDMHealthConcurrency = 25
	maxEDRGroups                    = 100
)

type sqlStore interface {
	GetDB() *gorm.DB
	GetStoreEngine() types.Engine
}

type fetchDevicesFunc func(
	context.Context,
	string,
	*providerConfig,
	*deviceIdentityFilter,
) ([]deviceSnapshot, error)

// Service implements the Dashboard EDR API and NetBird's integrated validator
// contract. PostgreSQL is the durable scheduler and cache; Redis is not used.
type Service struct {
	store        store.Store
	repository   *repository
	permissions  permissions.Manager
	events       activity.Store
	encryptor    *crypt.FieldEncrypt
	outbound     *outbound.Validator
	httpClient   httpDoer
	fetchDevices fetchDevicesFunc

	workerID                 string
	syncInterval             time.Duration
	cacheMaxAge              time.Duration
	syncTimeout              time.Duration
	fleetDMHealthConcurrency int
	signal                   chan struct{}
	stop                     chan struct{}
	stopped                  chan struct{}
	startOnce                sync.Once
	stopOnce                 sync.Once

	listenerMu sync.RWMutex
	listener   func(accountID string, peerIDs []string)
}

func NewService(
	dataStore store.Store,
	permissionsManager permissions.Manager,
	eventStore activity.Store,
	dataStoreEncryptionKey string,
) (*Service, error) {
	sql, ok := dataStore.(sqlStore)
	if !ok || sql.GetStoreEngine() != types.PostgresStoreEngine {
		return nil, fmt.Errorf("local EDR integrations require PostgreSQL")
	}
	encryptor, err := crypt.NewFieldEncrypt(dataStoreEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("local EDR requires a valid DataStoreEncryptionKey: %w", err)
	}
	outboundValidator, err := outbound.NewValidatorFromEnv()
	if err != nil {
		return nil, fmt.Errorf("configure local EDR outbound policy: %w", err)
	}
	repository := &repository{db: sql.GetDB()}
	migrationCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := repository.migrate(migrationCtx); err != nil {
		return nil, err
	}
	service := &Service{
		store:                    dataStore,
		repository:               repository,
		permissions:              permissionsManager,
		events:                   eventStore,
		encryptor:                encryptor,
		outbound:                 outboundValidator,
		httpClient:               outboundValidator.HTTPClient(),
		workerID:                 xid.New().String(),
		syncInterval:             syncIntervalFromEnv(),
		cacheMaxAge:              cacheMaxAgeFromEnv(),
		syncTimeout:              syncTimeoutFromEnv(),
		fleetDMHealthConcurrency: fleetDMHealthConcurrencyFromEnv(),
		signal:                   make(chan struct{}, 1),
		stop:                     make(chan struct{}),
		stopped:                  make(chan struct{}),
	}
	service.fetchDevices = service.fetchProviderDevices
	service.startWorker()
	return service, nil
}

func (s *Service) CreateIntune(
	ctx context.Context,
	accountID, userID string,
	request api.EDRIntuneRequest,
) (*api.EDRIntuneResponse, error) {
	config, enabled, err := configFromIntune(request, nil)
	if err != nil {
		return nil, err
	}
	integration, err := s.create(ctx, accountID, userID, providerIntune, request.Groups, config, enabled)
	if err != nil {
		return nil, err
	}
	return s.intuneResponse(ctx, integration, config)
}

func (s *Service) UpdateIntune(
	ctx context.Context,
	accountID, userID string,
	request api.EDRIntuneRequest,
) (*api.EDRIntuneResponse, error) {
	integration, previous, err := s.loadForUpdate(ctx, accountID, userID, providerIntune)
	if err != nil {
		return nil, err
	}
	config, enabled, err := configFromIntune(request, previous)
	if err != nil {
		return nil, err
	}
	if err := s.update(ctx, userID, integration, request.Groups, config, enabled); err != nil {
		return nil, err
	}
	return s.intuneResponse(ctx, integration, config)
}

func (s *Service) GetIntune(ctx context.Context, accountID, userID string) (*api.EDRIntuneResponse, error) {
	integration, config, err := s.get(ctx, accountID, userID, providerIntune)
	if err != nil {
		return nil, err
	}
	return s.intuneResponse(ctx, integration, config)
}

func (s *Service) CreateFalcon(
	ctx context.Context,
	accountID, userID string,
	request api.EDRFalconRequest,
) (*api.EDRFalconResponse, error) {
	config, enabled, err := configFromFalcon(request, nil)
	if err != nil {
		return nil, err
	}
	integration, err := s.create(ctx, accountID, userID, providerFalcon, request.Groups, config, enabled)
	if err != nil {
		return nil, err
	}
	return s.falconResponse(ctx, integration, config)
}

func (s *Service) UpdateFalcon(
	ctx context.Context,
	accountID, userID string,
	request api.EDRFalconRequest,
) (*api.EDRFalconResponse, error) {
	integration, previous, err := s.loadForUpdate(ctx, accountID, userID, providerFalcon)
	if err != nil {
		return nil, err
	}
	config, enabled, err := configFromFalcon(request, previous)
	if err != nil {
		return nil, err
	}
	if err := s.update(ctx, userID, integration, request.Groups, config, enabled); err != nil {
		return nil, err
	}
	return s.falconResponse(ctx, integration, config)
}

func (s *Service) GetFalcon(ctx context.Context, accountID, userID string) (*api.EDRFalconResponse, error) {
	integration, config, err := s.get(ctx, accountID, userID, providerFalcon)
	if err != nil {
		return nil, err
	}
	return s.falconResponse(ctx, integration, config)
}

func (s *Service) CreateSentinelOne(
	ctx context.Context,
	accountID, userID string,
	request api.EDRSentinelOneRequest,
) (*api.EDRSentinelOneResponse, error) {
	config, enabled, err := configFromSentinelOne(request, nil)
	if err != nil {
		return nil, err
	}
	integration, err := s.create(ctx, accountID, userID, providerSentinelOne, request.Groups, config, enabled)
	if err != nil {
		return nil, err
	}
	return s.sentinelOneResponse(ctx, integration, config)
}

func (s *Service) UpdateSentinelOne(
	ctx context.Context,
	accountID, userID string,
	request api.EDRSentinelOneRequest,
) (*api.EDRSentinelOneResponse, error) {
	integration, previous, err := s.loadForUpdate(ctx, accountID, userID, providerSentinelOne)
	if err != nil {
		return nil, err
	}
	config, enabled, err := configFromSentinelOne(request, previous)
	if err != nil {
		return nil, err
	}
	if err := s.update(ctx, userID, integration, request.Groups, config, enabled); err != nil {
		return nil, err
	}
	return s.sentinelOneResponse(ctx, integration, config)
}

func (s *Service) GetSentinelOne(
	ctx context.Context,
	accountID, userID string,
) (*api.EDRSentinelOneResponse, error) {
	integration, config, err := s.get(ctx, accountID, userID, providerSentinelOne)
	if err != nil {
		return nil, err
	}
	return s.sentinelOneResponse(ctx, integration, config)
}

func (s *Service) CreateHuntress(
	ctx context.Context,
	accountID, userID string,
	request api.EDRHuntressRequest,
) (*api.EDRHuntressResponse, error) {
	config, enabled, err := configFromHuntress(request, nil)
	if err != nil {
		return nil, err
	}
	integration, err := s.create(ctx, accountID, userID, providerHuntress, request.Groups, config, enabled)
	if err != nil {
		return nil, err
	}
	return s.huntressResponse(ctx, integration, config)
}

func (s *Service) UpdateHuntress(
	ctx context.Context,
	accountID, userID string,
	request api.EDRHuntressRequest,
) (*api.EDRHuntressResponse, error) {
	integration, previous, err := s.loadForUpdate(ctx, accountID, userID, providerHuntress)
	if err != nil {
		return nil, err
	}
	config, enabled, err := configFromHuntress(request, previous)
	if err != nil {
		return nil, err
	}
	if err := s.update(ctx, userID, integration, request.Groups, config, enabled); err != nil {
		return nil, err
	}
	return s.huntressResponse(ctx, integration, config)
}

func (s *Service) GetHuntress(
	ctx context.Context,
	accountID, userID string,
) (*api.EDRHuntressResponse, error) {
	integration, config, err := s.get(ctx, accountID, userID, providerHuntress)
	if err != nil {
		return nil, err
	}
	return s.huntressResponse(ctx, integration, config)
}

func (s *Service) CreateFleetDM(
	ctx context.Context,
	accountID, userID string,
	request api.EDRFleetDMRequest,
) (*api.EDRFleetDMResponse, error) {
	config, enabled, err := configFromFleetDM(request, nil)
	if err != nil {
		return nil, err
	}
	integration, err := s.create(ctx, accountID, userID, providerFleetDM, request.Groups, config, enabled)
	if err != nil {
		return nil, err
	}
	return s.fleetDMResponse(ctx, integration, config)
}

func (s *Service) UpdateFleetDM(
	ctx context.Context,
	accountID, userID string,
	request api.EDRFleetDMRequest,
) (*api.EDRFleetDMResponse, error) {
	integration, previous, err := s.loadForUpdate(ctx, accountID, userID, providerFleetDM)
	if err != nil {
		return nil, err
	}
	config, enabled, err := configFromFleetDM(request, previous)
	if err != nil {
		return nil, err
	}
	if err := s.update(ctx, userID, integration, request.Groups, config, enabled); err != nil {
		return nil, err
	}
	return s.fleetDMResponse(ctx, integration, config)
}

func (s *Service) GetFleetDM(
	ctx context.Context,
	accountID, userID string,
) (*api.EDRFleetDMResponse, error) {
	integration, config, err := s.get(ctx, accountID, userID, providerFleetDM)
	if err != nil {
		return nil, err
	}
	return s.fleetDMResponse(ctx, integration, config)
}

func (s *Service) Delete(
	ctx context.Context,
	accountID, userID, provider string,
) error {
	if !slices.Contains(providers, provider) {
		return status.Errorf(status.InvalidArgument, "unsupported EDR provider")
	}
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Delete)
	if err != nil {
		return err
	}
	var integration *edrmodel.Integration
	err = s.withRepositoryTransaction(ctx, func(transaction store.Store, repository *repository) error {
		integration, err = repository.getIntegrationForUpdate(ctx, accountID, provider)
		if err != nil {
			return err
		}
		if err := repository.deleteIntegration(ctx, accountID, provider); err != nil {
			return err
		}
		if !integration.Enabled {
			return nil
		}
		if err := s.clearIntegratedValidatorSettings(ctx, transaction, accountID); err != nil {
			return err
		}
		if err := repository.deleteAccountBypasses(ctx, accountID); err != nil {
			return status.Errorf(status.Internal, "failed to clear EDR bypasses")
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.audit(ctx, userID, accountID, integration, activity.IntegrationDeleted)
	s.notifyPeers(ctx, accountID, integration.Groups)
	return nil
}

func (s *Service) create(
	ctx context.Context,
	accountID, userID, provider string,
	groups []string,
	config *providerConfig,
	enabled bool,
) (*edrmodel.Integration, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Create)
	if err != nil {
		return nil, err
	}
	groups, err = s.validateGroups(ctx, accountID, groups)
	if err != nil {
		return nil, err
	}
	var snapshots []deviceSnapshot
	if enabled {
		snapshots, err = s.fetchForConfiguration(ctx, accountID, groups, provider, config)
		if err != nil {
			return nil, status.Errorf(status.InvalidArgument, "could not validate %s integration: %v", provider, err)
		}
	}
	encrypted, err := encryptProviderConfig(s.encryptor, config)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	integration := &edrmodel.Integration{
		AccountID:       accountID,
		Provider:        provider,
		CreatedBy:       userID,
		Enabled:         enabled,
		Groups:          groups,
		EncryptedConfig: encrypted,
		NextSyncAt:      now.Add(s.syncInterval),
	}
	err = s.withRepositoryTransaction(ctx, func(transaction store.Store, repository *repository) error {
		if enabled {
			current, err := repository.getEnabledIntegration(ctx, accountID)
			if err != nil {
				return err
			}
			if current != nil {
				return status.Errorf(
					status.PreconditionFailed,
					"disable the existing %s EDR integration before enabling %s",
					current.Provider,
					provider,
				)
			}
		}
		if err := repository.createIntegration(ctx, integration); err != nil {
			return err
		}
		if !enabled {
			return nil
		}
		if err := repository.replaceDevices(
			ctx,
			integration.ID,
			accountID,
			snapshotsToModels(snapshots),
			now,
			now.Add(s.syncInterval),
			"",
		); err != nil {
			return err
		}
		return s.applyIntegratedValidatorSettings(ctx, transaction, accountID, provider, groups)
	})
	if err != nil {
		return nil, err
	}
	if enabled {
		integration.LastSyncedAt = &now
	}
	s.audit(ctx, userID, accountID, integration, activity.IntegrationCreated)
	s.notifyPeers(ctx, accountID, groups)
	return integration, nil
}

func (s *Service) update(
	ctx context.Context,
	userID string,
	integration *edrmodel.Integration,
	groups []string,
	config *providerConfig,
	enabled bool,
) error {
	groups, err := s.validateGroups(ctx, integration.AccountID, groups)
	if err != nil {
		return err
	}
	var snapshots []deviceSnapshot
	if enabled {
		snapshots, err = s.fetchForConfiguration(
			ctx,
			integration.AccountID,
			groups,
			integration.Provider,
			config,
		)
		if err != nil {
			return status.Errorf(
				status.InvalidArgument,
				"could not validate %s integration: %v",
				integration.Provider,
				err,
			)
		}
	}
	encrypted, err := encryptProviderConfig(s.encryptor, config)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	loadedUpdatedAt := integration.UpdatedAt
	var previousGroups []string
	err = s.withRepositoryTransaction(ctx, func(transaction store.Store, repository *repository) error {
		current, err := repository.getIntegrationForUpdate(ctx, integration.AccountID, integration.Provider)
		if err != nil {
			return err
		}
		if !current.UpdatedAt.Equal(loadedUpdatedAt) {
			return status.Errorf(status.AlreadyExists, "EDR integration changed; reload and retry")
		}
		if enabled {
			enabledIntegration, err := repository.getEnabledIntegration(ctx, integration.AccountID)
			if err != nil {
				return err
			}
			if enabledIntegration != nil && enabledIntegration.Provider != integration.Provider {
				return status.Errorf(
					status.PreconditionFailed,
					"disable the existing %s EDR integration before enabling %s",
					enabledIntegration.Provider,
					integration.Provider,
				)
			}
		}
		previousGroups = slices.Clone(current.Groups)
		current.Groups = groups
		current.Enabled = enabled
		current.EncryptedConfig = encrypted
		current.NextSyncAt = now.Add(s.syncInterval)
		if err := repository.updateIntegration(ctx, current); err != nil {
			return err
		}
		if enabled {
			if err := repository.replaceDevices(
				ctx,
				current.ID,
				current.AccountID,
				snapshotsToModels(snapshots),
				now,
				now.Add(s.syncInterval),
				"",
			); err != nil {
				return err
			}
			if err := s.applyIntegratedValidatorSettings(
				ctx,
				transaction,
				current.AccountID,
				current.Provider,
				groups,
			); err != nil {
				return err
			}
			current.LastSyncedAt = &now
		} else {
			enabledIntegration, err := repository.getEnabledIntegration(ctx, current.AccountID)
			if err != nil {
				return err
			}
			if enabledIntegration == nil {
				if err := s.clearIntegratedValidatorSettings(ctx, transaction, current.AccountID); err != nil {
					return err
				}
				if err := repository.deleteAccountBypasses(ctx, current.AccountID); err != nil {
					return status.Errorf(status.Internal, "failed to clear EDR bypasses")
				}
			}
			current.LastSyncedAt = nil
		}
		*integration = *current
		return nil
	})
	if err != nil {
		return err
	}
	integration.UpdatedAt = now
	s.audit(ctx, userID, integration.AccountID, integration, activity.IntegrationUpdated)
	s.notifyPeers(ctx, integration.AccountID, append(previousGroups, groups...))
	return nil
}

func (s *Service) get(
	ctx context.Context,
	accountID, userID, provider string,
) (*edrmodel.Integration, *providerConfig, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Read)
	if err != nil {
		return nil, nil, err
	}
	integration, err := s.repository.getIntegration(ctx, accountID, provider)
	if err != nil {
		return nil, nil, err
	}
	config, err := decryptProviderConfig(s.encryptor, integration.EncryptedConfig)
	if err != nil {
		return nil, nil, err
	}
	return integration, config, nil
}

func (s *Service) loadForUpdate(
	ctx context.Context,
	accountID, userID, provider string,
) (*edrmodel.Integration, *providerConfig, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, nil, err
	}
	integration, err := s.repository.getIntegration(ctx, accountID, provider)
	if err != nil {
		return nil, nil, err
	}
	config, err := decryptProviderConfig(s.encryptor, integration.EncryptedConfig)
	if err != nil {
		return nil, nil, err
	}
	return integration, config, nil
}

func (s *Service) fetchForConfiguration(
	ctx context.Context,
	accountID string,
	groups []string,
	provider string,
	config *providerConfig,
) ([]deviceSnapshot, error) {
	filter, err := s.deviceIdentityFilterForGroups(ctx, accountID, groups)
	if err != nil {
		return nil, err
	}
	syncCtx, cancel := context.WithTimeout(ctx, s.syncTimeout)
	defer cancel()
	return s.fetchDevices(syncCtx, provider, config, filter)
}

func (s *Service) deviceIdentityFilterForGroups(
	ctx context.Context,
	accountID string,
	groups []string,
) (*deviceIdentityFilter, error) {
	filter := newDeviceIdentityFilter()
	peerIDs, err := s.store.GetPeerIDsByGroups(ctx, accountID, groups)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to load EDR group peers")
	}
	if len(peerIDs) == 0 {
		return filter, nil
	}
	selected := make(map[string]struct{}, len(peerIDs))
	for _, peerID := range peerIDs {
		selected[peerID] = struct{}{}
	}
	peers, err := s.store.GetAccountPeers(ctx, store.LockingStrengthNone, accountID, "", "")
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to load EDR peers")
	}
	for _, peer := range peers {
		if _, ok := selected[peer.ID]; !ok {
			continue
		}
		filter.add(
			peer.Meta.SystemSerialNumber,
			firstNonEmpty(peer.Meta.Hostname, peer.Name),
		)
	}
	return filter, nil
}

func (s *Service) validateGroups(
	ctx context.Context,
	accountID string,
	groups []string,
) ([]string, error) {
	if len(groups) == 0 || len(groups) > maxEDRGroups {
		return nil, status.Errorf(status.InvalidArgument, "EDR integration requires between 1 and %d groups", maxEDRGroups)
	}
	result := make([]string, 0, len(groups))
	seen := make(map[string]struct{}, len(groups))
	for _, groupID := range groups {
		groupID = strings.TrimSpace(groupID)
		if groupID == "" {
			return nil, status.Errorf(status.InvalidArgument, "EDR group ID must not be empty")
		}
		if _, ok := seen[groupID]; ok {
			return nil, status.Errorf(status.InvalidArgument, "EDR groups must be unique")
		}
		seen[groupID] = struct{}{}
		result = append(result, groupID)
	}
	available, err := s.store.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, result)
	if err != nil {
		return nil, err
	}
	if len(available) != len(result) {
		return nil, status.Errorf(status.InvalidArgument, "one or more EDR groups do not exist")
	}
	slices.Sort(result)
	return result, nil
}

func (s *Service) requirePermission(
	ctx context.Context,
	accountID, userID string,
	operation operations.Operation,
) (context.Context, error) {
	ok, permissionCtx, err := s.permissions.ValidateUserPermissions(
		ctx,
		accountID,
		userID,
		modules.EDR,
		operation,
	)
	if err != nil {
		return permissionCtx, status.NewPermissionValidationError(err)
	}
	if !ok {
		return permissionCtx, status.NewPermissionDeniedError()
	}
	return permissionCtx, nil
}

func (s *Service) applyIntegratedValidatorSettings(
	ctx context.Context,
	dataStore store.Store,
	accountID, provider string,
	groups []string,
) error {
	settings, err := dataStore.GetAccountSettings(ctx, store.LockingStrengthUpdate, accountID)
	if err != nil {
		return err
	}
	if settings.Extra == nil {
		settings.Extra = &types.ExtraSettings{}
	}
	settings.Extra.PeerApprovalEnabled = false
	settings.Extra.IntegratedValidator = provider
	settings.Extra.IntegratedValidatorGroups = slices.Clone(groups)
	return dataStore.SaveAccountSettings(ctx, accountID, settings)
}

func (s *Service) clearIntegratedValidatorSettings(
	ctx context.Context,
	dataStore store.Store,
	accountID string,
) error {
	settings, err := dataStore.GetAccountSettings(ctx, store.LockingStrengthUpdate, accountID)
	if err != nil {
		return err
	}
	if settings.Extra == nil {
		return nil
	}
	settings.Extra.IntegratedValidator = ""
	settings.Extra.IntegratedValidatorGroups = []string{}
	return dataStore.SaveAccountSettings(ctx, accountID, settings)
}

func (s *Service) withRepositoryTransaction(
	ctx context.Context,
	operation func(store.Store, *repository) error,
) error {
	return s.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		sqlTransaction, ok := transaction.(sqlStore)
		if !ok || sqlTransaction.GetStoreEngine() != types.PostgresStoreEngine {
			return status.Errorf(status.Internal, "local EDR transaction requires PostgreSQL")
		}
		return operation(transaction, &repository{db: sqlTransaction.GetDB()})
	})
}

func (s *Service) groupsToAPI(ctx context.Context, integration *edrmodel.Integration) ([]api.Group, error) {
	groups, err := s.store.GetGroupsByIDs(
		ctx,
		store.LockingStrengthNone,
		integration.AccountID,
		integration.Groups,
	)
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to load EDR groups")
	}
	result := make([]api.Group, 0, len(integration.Groups))
	for _, groupID := range integration.Groups {
		group, ok := groups[groupID]
		if !ok {
			continue
		}
		issued := api.GroupIssued(group.Issued)
		result = append(result, api.Group{
			Id:             group.ID,
			Name:           group.Name,
			Issued:         &issued,
			Peers:          []api.PeerMinimum{},
			PeersCount:     len(group.Peers),
			Resources:      []api.Resource{},
			ResourcesCount: len(group.Resources),
		})
	}
	return result, nil
}

func (s *Service) baseResponse(
	ctx context.Context,
	integration *edrmodel.Integration,
) (int64, []api.Group, *time.Time, *string, error) {
	if integration.ID > math.MaxInt64 {
		return 0, nil, nil, nil, status.Errorf(status.Internal, "EDR integration ID is out of range")
	}
	groups, err := s.groupsToAPI(ctx, integration)
	if err != nil {
		return 0, nil, nil, nil, err
	}
	var lastSyncedAt *time.Time
	if integration.LastSyncedAt != nil {
		value := integration.LastSyncedAt.UTC()
		lastSyncedAt = &value
	}
	var lastError *string
	if integration.LastError != "" {
		value := integration.LastError
		lastError = &value
	}
	return int64(integration.ID), groups, lastSyncedAt, lastError, nil
}

func (s *Service) intuneResponse(
	ctx context.Context,
	integration *edrmodel.Integration,
	config *providerConfig,
) (*api.EDRIntuneResponse, error) {
	id, groups, lastSyncedAt, lastError, err := s.baseResponse(ctx, integration)
	if err != nil {
		return nil, err
	}
	return &api.EDRIntuneResponse{
		Id:                 id,
		AccountId:          integration.AccountID,
		CreatedBy:          integration.CreatedBy,
		CreatedAt:          integration.CreatedAt,
		UpdatedAt:          integration.UpdatedAt,
		LastSyncedAt:       lastSyncedAt,
		LastError:          lastError,
		ClientId:           config.ClientID,
		TenantId:           config.TenantID,
		Groups:             groups,
		LastSyncedInterval: config.LastSyncedInterval,
		Enabled:            integration.Enabled,
	}, nil
}

func (s *Service) falconResponse(
	ctx context.Context,
	integration *edrmodel.Integration,
	config *providerConfig,
) (*api.EDRFalconResponse, error) {
	id, groups, lastSyncedAt, lastError, err := s.baseResponse(ctx, integration)
	if err != nil {
		return nil, err
	}
	return &api.EDRFalconResponse{
		Id:                id,
		AccountId:         integration.AccountID,
		CreatedBy:         integration.CreatedBy,
		CreatedAt:         integration.CreatedAt,
		UpdatedAt:         integration.UpdatedAt,
		LastSyncedAt:      lastSyncedAt,
		LastError:         lastError,
		CloudId:           config.CloudID,
		Groups:            groups,
		ZtaScoreThreshold: config.ZTAScoreThreshold,
		Enabled:           integration.Enabled,
	}, nil
}

func (s *Service) sentinelOneResponse(
	ctx context.Context,
	integration *edrmodel.Integration,
	config *providerConfig,
) (*api.EDRSentinelOneResponse, error) {
	id, groups, lastSyncedAt, lastError, err := s.baseResponse(ctx, integration)
	if err != nil {
		return nil, err
	}
	return &api.EDRSentinelOneResponse{
		Id:                 id,
		AccountId:          integration.AccountID,
		CreatedBy:          integration.CreatedBy,
		CreatedAt:          integration.CreatedAt,
		UpdatedAt:          integration.UpdatedAt,
		LastSyncedAt:       lastSyncedAt,
		LastError:          lastError,
		ApiUrl:             config.APIURL,
		Groups:             groups,
		LastSyncedInterval: config.LastSyncedInterval,
		MatchAttributes:    config.SentinelOneMatch,
		Enabled:            integration.Enabled,
	}, nil
}

func (s *Service) huntressResponse(
	ctx context.Context,
	integration *edrmodel.Integration,
	config *providerConfig,
) (*api.EDRHuntressResponse, error) {
	id, groups, lastSyncedAt, lastError, err := s.baseResponse(ctx, integration)
	if err != nil {
		return nil, err
	}
	return &api.EDRHuntressResponse{
		Id:                 id,
		AccountId:          integration.AccountID,
		CreatedBy:          integration.CreatedBy,
		CreatedAt:          integration.CreatedAt,
		UpdatedAt:          integration.UpdatedAt,
		LastSyncedAt:       lastSyncedAt,
		LastError:          lastError,
		Groups:             groups,
		LastSyncedInterval: config.LastSyncedInterval,
		MatchAttributes:    config.HuntressMatch,
		Enabled:            integration.Enabled,
	}, nil
}

func (s *Service) fleetDMResponse(
	ctx context.Context,
	integration *edrmodel.Integration,
	config *providerConfig,
) (*api.EDRFleetDMResponse, error) {
	id, groups, lastSyncedAt, lastError, err := s.baseResponse(ctx, integration)
	if err != nil {
		return nil, err
	}
	return &api.EDRFleetDMResponse{
		Id:                 id,
		AccountId:          integration.AccountID,
		CreatedBy:          integration.CreatedBy,
		CreatedAt:          integration.CreatedAt,
		UpdatedAt:          integration.UpdatedAt,
		LastSyncedAt:       lastSyncedAt,
		LastError:          lastError,
		ApiUrl:             config.APIURL,
		Groups:             groups,
		LastSyncedInterval: config.LastSyncedInterval,
		MatchAttributes:    config.FleetDMMatch,
		Enabled:            integration.Enabled,
	}, nil
}

func (s *Service) audit(
	ctx context.Context,
	userID, accountID string,
	integration *edrmodel.Integration,
	code activity.Activity,
) {
	if s.events == nil {
		return
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_, err := s.events.Save(auditCtx, &activity.Event{
		Timestamp:   time.Now().UTC(),
		Activity:    code,
		InitiatorID: userID,
		TargetID:    fmt.Sprint(integration.ID),
		AccountID:   accountID,
		Meta: map[string]any{
			"type":     "edr",
			"provider": integration.Provider,
		},
	})
	if err != nil {
		log.WithContext(ctx).WithError(err).Warn("failed to store EDR audit event")
	}
}

func syncIntervalFromEnv() time.Duration {
	value := strings.TrimSpace(os.Getenv("NB_LOCAL_EDR_SYNC_INTERVAL"))
	if value == "" {
		return defaultSyncInterval
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < time.Minute || parsed > time.Hour {
		log.Warnf(
			"invalid NB_LOCAL_EDR_SYNC_INTERVAL %q; using %s",
			value,
			defaultSyncInterval,
		)
		return defaultSyncInterval
	}
	return parsed
}

func cacheMaxAgeFromEnv() time.Duration {
	value := strings.TrimSpace(os.Getenv("NB_LOCAL_EDR_CACHE_MAX_AGE"))
	if value == "" {
		return defaultCacheMaxAge
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < 5*time.Minute || parsed > 24*time.Hour {
		log.Warnf(
			"invalid NB_LOCAL_EDR_CACHE_MAX_AGE %q; using %s",
			value,
			defaultCacheMaxAge,
		)
		return defaultCacheMaxAge
	}
	return parsed
}

func syncTimeoutFromEnv() time.Duration {
	value := strings.TrimSpace(os.Getenv("NB_LOCAL_EDR_SYNC_TIMEOUT"))
	if value == "" {
		return defaultSyncTimeout
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < 30*time.Second || parsed > 30*time.Minute {
		log.Warnf(
			"invalid NB_LOCAL_EDR_SYNC_TIMEOUT %q; using %s",
			value,
			defaultSyncTimeout,
		)
		return defaultSyncTimeout
	}
	return parsed
}

func fleetDMHealthConcurrencyFromEnv() int {
	value := strings.TrimSpace(os.Getenv("NB_LOCAL_EDR_FLEETDM_HEALTH_CONCURRENCY"))
	if value == "" {
		return defaultFleetDMHealthConcurrency
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 || parsed > 100 {
		log.Warnf(
			"invalid NB_LOCAL_EDR_FLEETDM_HEALTH_CONCURRENCY %q; using %d",
			value,
			defaultFleetDMHealthConcurrency,
		)
		return defaultFleetDMHealthConcurrency
	}
	return parsed
}
