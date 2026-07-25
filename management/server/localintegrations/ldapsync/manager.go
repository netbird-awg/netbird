package ldapsync

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	ldapsyncmodel "github.com/netbirdio/netbird/management/server/localintegrations/ldapsync/model"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	connectorTestLimit  = 5
	connectorTestWindow = time.Minute
	defaultRunPageSize  = 20
	maxRunPageSize      = 100
)

// Service owns local OpenLDAP diagnostics, synchronization configuration, and
// the durable PostgreSQL worker.
type Service struct {
	store       syncStore
	permissions permissions.Manager
	idpManager  idp.Manager
	events      account.Manager
	syncKey     []byte
	metrics     *syncMetrics
	workerID    string

	rateMu    sync.Mutex
	rateCalls map[string][]time.Time
	startOnce sync.Once
}

// syncStore keeps local integration persistence out of NetBird's central
// Store interface, minimizing the upstream merge surface of this extension.
type syncStore interface {
	store.Store
	ListLDAPSyncConfigs(ctx context.Context, accountID string) ([]*ldapsyncmodel.Config, error)
	GetLDAPSyncConfig(ctx context.Context, accountID, connectorID string) (*ldapsyncmodel.Config, error)
	SaveLDAPSyncConfig(ctx context.Context, config *ldapsyncmodel.Config, expectedRevision int64) error
	UpdateLDAPSyncConfigRuntime(ctx context.Context, config *ldapsyncmodel.Config) error
	CreateLDAPSyncRun(ctx context.Context, run *ldapsyncmodel.Run) error
	GetLDAPSyncRun(ctx context.Context, accountID, connectorID, runID string) (*ldapsyncmodel.Run, error)
	CancelLDAPSyncRun(ctx context.Context, accountID, connectorID, runID string, finishedAt time.Time) (*ldapsyncmodel.Run, error)
	ListLDAPSyncRuns(ctx context.Context, accountID, connectorID string, offset, limit int) ([]*ldapsyncmodel.Run, int64, error)
	CountLDAPSyncRuns(ctx context.Context, statuses ...string) (int64, error)
	ClaimLDAPSyncRun(ctx context.Context, now time.Time, leaseDuration time.Duration, leaseOwner string) (*ldapsyncmodel.Run, error)
	RenewLDAPSyncRunLease(ctx context.Context, accountID, connectorID, runID, leaseOwner string, now time.Time, leaseDuration time.Duration) (bool, error)
	UpdateLDAPSyncRun(ctx context.Context, run *ldapsyncmodel.Run) error
	UpdateLDAPSyncRunOwned(ctx context.Context, run *ldapsyncmodel.Run, leaseOwner string) (bool, error)
	GetLDAPSyncObjects(ctx context.Context, accountID, connectorID, objectType string) ([]*ldapsyncmodel.Object, error)
	SaveLDAPSyncObjects(ctx context.Context, objects []*ldapsyncmodel.Object) error
}

func NewService(dataStoreEncryptionKey string, dataStore store.Store, permissionsManager permissions.Manager, idpManager idp.Manager, events account.Manager, meter metric.Meter) *Service {
	syncDataStore, ok := dataStore.(syncStore)
	if !ok {
		panic("configured NetBird store does not implement local LDAP synchronization persistence")
	}
	var syncKey []byte
	if dataStoreEncryptionKey != "" {
		mac := hmac.New(sha256.New, []byte(dataStoreEncryptionKey))
		_, _ = mac.Write([]byte("netbird/local-ldap-sync/v1"))
		syncKey = mac.Sum(nil)
	}
	return &Service{
		store:       syncDataStore,
		permissions: permissionsManager,
		idpManager:  idpManager,
		events:      events,
		syncKey:     syncKey,
		metrics:     newSyncMetrics(meter),
		workerID:    xid.New().String(),
		rateCalls:   make(map[string][]time.Time),
	}
}

func (s *Service) TestConnector(ctx context.Context, accountID, connectorID, userID string) (*ConnectorTestResponse, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}
	if err := s.allowConnectorTest(accountID, connectorID, userID); err != nil {
		return nil, err
	}

	diagnostic, err := s.testConnector(ctx, accountID, connectorID)
	s.metrics.recordConnectorTest(ctx, diagnostic, err)
	s.events.StoreEvent(ctx, userID, connectorID, accountID, activity.LocalLDAPConnectorTested, map[string]any{
		"success": err == nil,
	})
	if err != nil {
		return nil, err
	}
	return &ConnectorTestResponse{
		Status:    "ok",
		Checks:    diagnostic.Checks,
		LatencyMS: diagnostic.Latency.Milliseconds(),
		TestedAt:  diagnostic.TestedAt,
	}, nil
}

func (s *Service) ListConfigs(ctx context.Context, accountID, userID string) ([]*ldapsyncmodel.Config, error) {
	if _, err := s.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}
	return s.store.ListLDAPSyncConfigs(ctx, accountID)
}

func (s *Service) GetConfig(ctx context.Context, accountID, connectorID, userID string) (*ldapsyncmodel.Config, error) {
	if _, err := s.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}
	return s.store.GetLDAPSyncConfig(ctx, accountID, connectorID)
}

func (s *Service) SaveConfig(ctx context.Context, accountID, connectorID, userID string, request ConfigRequest) (*ldapsyncmodel.Config, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}
	if err := s.requirePostgresAndKey(); err != nil {
		return nil, err
	}
	if _, err := s.ldapConnector(ctx, accountID, connectorID); err != nil {
		return nil, err
	}

	normalized, err := s.normalizeConfigRequest(ctx, accountID, request)
	if err != nil {
		return nil, err
	}

	existing, getErr := s.store.GetLDAPSyncConfig(ctx, accountID, connectorID)
	creating := false
	if getErr != nil {
		if !isStatusType(getErr, status.NotFound) {
			return nil, getErr
		}
		creating = true
		if request.Revision != 0 {
			return nil, status.Errorf(status.AlreadyExists, "new local LDAP sync config revision must be zero")
		}
		existing = &ldapsyncmodel.Config{AccountID: accountID, ConnectorID: connectorID}
	} else if request.Revision != existing.Revision {
		return nil, status.Errorf(status.AlreadyExists, "local LDAP sync config revision conflict")
	}

	wasEnabled := existing.Enabled
	existing.Enabled = normalized.Enabled
	existing.IntervalMinutes = normalized.IntervalMinutes
	existing.SyncScopeGroups = normalized.SyncScopeGroups
	existing.GroupMappings = normalized.GroupMappings
	existing.DeprovisionAction = normalized.DeprovisionAction
	existing.ConflictPolicy = normalized.ConflictPolicy
	if existing.Enabled {
		if !wasEnabled || existing.NextRunAt == nil {
			now := time.Now().UTC()
			existing.NextRunAt = &now
		}
	} else {
		existing.NextRunAt = nil
	}

	expectedRevision := request.Revision
	if creating {
		expectedRevision = 0
	}
	if err := s.store.SaveLDAPSyncConfig(ctx, existing, expectedRevision); err != nil {
		return nil, err
	}

	s.events.StoreEvent(ctx, userID, connectorID, accountID, activity.LocalLDAPSyncConfigUpdated, map[string]any{
		"enabled":          existing.Enabled,
		"interval_minutes": existing.IntervalMinutes,
		"revision":         existing.Revision,
	})
	if existing.Enabled && (creating || !wasEnabled) {
		_, _ = s.createRun(ctx, existing, userID, ldapsyncmodel.RunTriggerInitial, "", "")
	}
	return existing, nil
}

func (s *Service) Pause(ctx context.Context, accountID, connectorID, userID string) (*ldapsyncmodel.Config, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}
	config, err := s.store.GetLDAPSyncConfig(ctx, accountID, connectorID)
	if err != nil {
		return nil, err
	}
	expectedRevision := config.Revision
	config.PausedReason = "paused_by_user"
	config.NextRunAt = nil
	if err := s.store.SaveLDAPSyncConfig(ctx, config, expectedRevision); err != nil {
		return nil, err
	}
	s.events.StoreEvent(ctx, userID, connectorID, accountID, activity.LocalLDAPSyncPaused, nil)
	return config, nil
}

func (s *Service) Resume(ctx context.Context, accountID, connectorID, userID string) (*ldapsyncmodel.Config, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}
	if _, err := s.testConnector(ctx, accountID, connectorID); err != nil {
		return nil, err
	}
	config, err := s.store.GetLDAPSyncConfig(ctx, accountID, connectorID)
	if err != nil {
		return nil, err
	}
	expectedRevision := config.Revision
	config.Enabled = true
	config.PausedReason = ""
	config.FailureCount = 0
	now := time.Now().UTC()
	config.NextRunAt = &now
	if err := s.store.SaveLDAPSyncConfig(ctx, config, expectedRevision); err != nil {
		return nil, err
	}
	s.events.StoreEvent(ctx, userID, connectorID, accountID, activity.LocalLDAPSyncResumed, nil)
	_, _ = s.createRun(ctx, config, userID, ldapsyncmodel.RunTriggerManual, "", "")
	return config, nil
}

func (s *Service) GetRun(ctx context.Context, accountID, connectorID, runID, userID string) (*ldapsyncmodel.Run, error) {
	if _, err := s.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}
	return s.store.GetLDAPSyncRun(ctx, accountID, connectorID, runID)
}

func (s *Service) CancelRun(ctx context.Context, accountID, connectorID, runID, userID string) (*ldapsyncmodel.Run, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	run, err := s.store.CancelLDAPSyncRun(ctx, accountID, connectorID, runID, now)
	if err != nil {
		return nil, err
	}
	s.events.StoreEvent(ctx, userID, connectorID, accountID, activity.LocalLDAPSyncRunCancelled, map[string]any{"run_id": run.ID})
	s.metrics.recordRun(ctx, run)
	return run, nil
}

func (s *Service) ListRuns(ctx context.Context, accountID, connectorID, userID string, offset, limit int) (*RunListResponse, error) {
	if _, err := s.requirePermission(ctx, accountID, userID, operations.Read); err != nil {
		return nil, err
	}
	if offset < 0 {
		return nil, status.Errorf(status.InvalidArgument, "offset must not be negative")
	}
	if limit == 0 {
		limit = defaultRunPageSize
	}
	if limit < 1 || limit > maxRunPageSize {
		return nil, status.Errorf(status.InvalidArgument, "limit must be between 1 and %d", maxRunPageSize)
	}
	runs, total, err := s.store.ListLDAPSyncRuns(ctx, accountID, connectorID, offset, limit)
	if err != nil {
		return nil, err
	}
	return &RunListResponse{Items: runs, Total: total, Offset: offset, Limit: limit}, nil
}

func (s *Service) requirePermission(ctx context.Context, accountID, userID string, operation operations.Operation) (context.Context, error) {
	ok, permissionCtx, err := s.permissions.ValidateUserPermissions(ctx, accountID, userID, modules.IdentityProviders, operation)
	if err != nil {
		return permissionCtx, status.NewPermissionValidationError(err)
	}
	if !ok {
		return permissionCtx, status.NewPermissionDeniedError()
	}
	return permissionCtx, nil
}

func (s *Service) ldapConnector(ctx context.Context, accountID, connectorID string) (*dex.ConnectorConfig, error) {
	embedded, ok := s.idpManager.(*idp.EmbeddedIdPManager)
	if !ok || embedded == nil {
		return nil, status.Errorf(status.PreconditionFailed, "local LDAP integration requires embedded identity provider")
	}
	connector, err := embedded.GetConnector(ctx, connectorID)
	if err != nil {
		return nil, status.Errorf(status.NotFound, "LDAP connector not found")
	}
	if connector.Type != string(types.IdentityProviderTypeLDAP) || connector.LDAP == nil {
		return nil, status.Errorf(status.InvalidArgument, "identity provider is not an LDAP connector")
	}
	if connector.AccountID == "" {
		accounts := s.store.GetAllAccounts(ctx)
		if len(accounts) == 1 && accounts[0].Id == accountID {
			connector.AccountID = accountID
			if err := embedded.UpdateConnector(ctx, connector); err != nil {
				return nil, status.Errorf(status.Internal, "failed to claim legacy LDAP connector")
			}
		}
	}
	if connector.AccountID == "" || connector.AccountID != accountID {
		return nil, status.Errorf(status.NotFound, "LDAP connector not found")
	}
	return connector, nil
}

func (s *Service) testConnector(ctx context.Context, accountID, connectorID string) (*dex.LDAPDiagnostic, error) {
	connector, err := s.ldapConnector(ctx, accountID, connectorID)
	if err != nil {
		return nil, err
	}
	return dex.TestLDAPConnection(ctx, connector.LDAP)
}

func (s *Service) requirePostgresAndKey() error {
	if s.store.GetStoreEngine() != types.PostgresStoreEngine {
		return status.Errorf(status.PreconditionFailed, "local LDAP synchronization requires PostgreSQL")
	}
	if len(s.syncKey) == 0 {
		return status.Errorf(status.PreconditionFailed, "DataStoreEncryptionKey is required for stable LDAP synchronization identifiers")
	}
	return nil
}

func (s *Service) normalizeConfigRequest(ctx context.Context, accountID string, request ConfigRequest) (*ConfigRequest, error) {
	if request.IntervalMinutes < ldapsyncmodel.ConfigMinIntervalMinutes || request.IntervalMinutes > ldapsyncmodel.ConfigMaxIntervalMinutes {
		return nil, status.Errorf(status.InvalidArgument, "interval_minutes must be between %d and %d", ldapsyncmodel.ConfigMinIntervalMinutes, ldapsyncmodel.ConfigMaxIntervalMinutes)
	}
	request.SyncScopeGroups = normalizeStrings(request.SyncScopeGroups)
	if len(request.SyncScopeGroups) == 0 {
		request.SyncScopeGroups = []string{ldapsyncmodel.DefaultScopeGroup}
	}
	if !request.AllowWithoutDefaultScope && !slices.Contains(request.SyncScopeGroups, ldapsyncmodel.DefaultScopeGroup) {
		return nil, status.Errorf(status.InvalidArgument, "sync_scope_groups must contain %q unless advanced override is explicitly confirmed", ldapsyncmodel.DefaultScopeGroup)
	}

	switch request.DeprovisionAction {
	case "":
		request.DeprovisionAction = ldapsyncmodel.DeprovisionDisable
	case ldapsyncmodel.DeprovisionDisable, ldapsyncmodel.DeprovisionIgnore:
	default:
		return nil, status.Errorf(status.InvalidArgument, "deprovision_action must be disable or ignore")
	}
	if request.ConflictPolicy == "" {
		request.ConflictPolicy = ldapsyncmodel.ConflictSkip
	}
	if request.ConflictPolicy != ldapsyncmodel.ConflictSkip {
		return nil, status.Errorf(status.InvalidArgument, "conflict_policy must be skip")
	}

	seenMappings := make(map[string]struct{}, len(request.GroupMappings))
	groupIDs := make([]string, 0)
	for index := range request.GroupMappings {
		mapping := &request.GroupMappings[index]
		mapping.LDAPGroup = strings.TrimSpace(mapping.LDAPGroup)
		if mapping.LDAPGroup == "" {
			return nil, status.Errorf(status.InvalidArgument, "LDAP group mapping name is required")
		}
		key := strings.ToLower(mapping.LDAPGroup)
		if _, ok := seenMappings[key]; ok {
			return nil, status.Errorf(status.InvalidArgument, "duplicate LDAP group mapping %q", mapping.LDAPGroup)
		}
		seenMappings[key] = struct{}{}
		mapping.NetBirdAutoGroupIDs = normalizeStrings(mapping.NetBirdAutoGroupIDs)
		groupIDs = append(groupIDs, mapping.NetBirdAutoGroupIDs...)
	}
	groupIDs = normalizeStrings(groupIDs)
	if len(groupIDs) > 0 {
		groups, err := s.store.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, groupIDs)
		if err != nil {
			return nil, err
		}
		if len(groups) != len(groupIDs) {
			return nil, status.Errorf(status.InvalidArgument, "one or more NetBird Auto Groups do not exist in this account")
		}
	}
	return &request, nil
}

func (s *Service) createRun(ctx context.Context, config *ldapsyncmodel.Config, initiatedBy, trigger, sourceFingerprint, tokenHash string) (*ldapsyncmodel.Run, error) {
	now := time.Now().UTC()
	run := &ldapsyncmodel.Run{
		ID:                    xid.New().String(),
		AccountID:             config.AccountID,
		ConnectorID:           config.ConnectorID,
		Status:                ldapsyncmodel.RunStatusQueued,
		Trigger:               trigger,
		InitiatedBy:           initiatedBy,
		ConfigRevision:        config.Revision,
		SourceFingerprint:     sourceFingerprint,
		ConfirmationTokenHash: tokenHash,
		QueuedAt:              now,
	}
	if err := s.store.CreateLDAPSyncRun(ctx, run); err != nil {
		return nil, err
	}
	return run, nil
}

func (s *Service) allowConnectorTest(accountID, connectorID, userID string) error {
	now := time.Now()
	cutoff := now.Add(-connectorTestWindow)
	key := accountID + "\x00" + connectorID + "\x00" + userID
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	calls := s.rateCalls[key]
	kept := calls[:0]
	for _, call := range calls {
		if call.After(cutoff) {
			kept = append(kept, call)
		}
	}
	if len(kept) >= connectorTestLimit {
		s.rateCalls[key] = kept
		return status.Errorf(status.TooManyRequests, "LDAP connector test rate limit exceeded")
	}
	s.rateCalls[key] = append(kept, now)
	return nil
}

func normalizeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func isStatusType(err error, expected status.Type) bool {
	var typed *status.Error
	return errors.As(err, &typed) && typed.Type() == expected
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:6])
}
