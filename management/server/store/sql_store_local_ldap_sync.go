package store

import (
	"context"
	"errors"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	ldapsyncmodel "github.com/netbirdio/netbird/management/server/localintegrations/ldapsync/model"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) ListLDAPSyncConfigs(ctx context.Context, accountID string) ([]*ldapsyncmodel.Config, error) {
	var configs []*ldapsyncmodel.Config
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Order("connector_id ASC").Find(&configs).Error; err != nil {
		log.WithContext(ctx).WithError(err).Error("failed to list local LDAP sync configs")
		return nil, status.Errorf(status.Internal, "failed to list local LDAP sync configs")
	}
	return configs, nil
}

func (s *SqlStore) HasLDAPSyncConfig(ctx context.Context, accountID, connectorID string) (bool, error) {
	var count int64
	if err := s.db.WithContext(ctx).Model(&ldapsyncmodel.Config{}).
		Where("account_id = ? AND connector_id = ?", accountID, connectorID).
		Count(&count).Error; err != nil {
		return false, status.Errorf(status.Internal, "failed to check local LDAP sync config")
	}
	return count > 0, nil
}

func (s *SqlStore) GetLDAPSyncConfig(ctx context.Context, accountID, connectorID string) (*ldapsyncmodel.Config, error) {
	var config ldapsyncmodel.Config
	err := s.db.WithContext(ctx).Where("account_id = ? AND connector_id = ?", accountID, connectorID).Take(&config).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Errorf(status.NotFound, "local LDAP sync config not found")
	}
	if err != nil {
		log.WithContext(ctx).WithError(err).Error("failed to get local LDAP sync config")
		return nil, status.Errorf(status.Internal, "failed to get local LDAP sync config")
	}
	return &config, nil
}

func (s *SqlStore) SaveLDAPSyncConfig(ctx context.Context, config *ldapsyncmodel.Config, expectedRevision int64) error {
	if config.ID == 0 {
		config.Revision = 1
		if err := s.db.WithContext(ctx).Create(config).Error; err != nil {
			log.WithContext(ctx).WithError(err).Error("failed to create local LDAP sync config")
			return status.Errorf(status.AlreadyExists, "local LDAP sync config already exists")
		}
		return nil
	}

	config.Revision = expectedRevision + 1
	result := s.db.WithContext(ctx).
		Model(&ldapsyncmodel.Config{}).
		Where("id = ? AND account_id = ? AND connector_id = ? AND revision = ?", config.ID, config.AccountID, config.ConnectorID, expectedRevision).
		Select(
			"enabled", "interval_minutes", "sync_scope_groups", "group_mappings",
			"deprovision_action", "conflict_policy", "failure_count", "paused_reason",
			"next_run_at", "last_success_at", "revision", "updated_at",
		).
		Updates(config)
	if result.Error != nil {
		log.WithContext(ctx).WithError(result.Error).Error("failed to update local LDAP sync config")
		return status.Errorf(status.Internal, "failed to update local LDAP sync config")
	}
	if result.RowsAffected != 1 {
		return status.Errorf(status.AlreadyExists, "local LDAP sync config revision conflict")
	}
	return nil
}

func (s *SqlStore) UpdateLDAPSyncConfigRuntime(ctx context.Context, config *ldapsyncmodel.Config) error {
	result := s.db.WithContext(ctx).
		Model(&ldapsyncmodel.Config{}).
		Where("id = ? AND account_id = ? AND connector_id = ?", config.ID, config.AccountID, config.ConnectorID).
		Updates(map[string]any{
			"failure_count":   config.FailureCount,
			"paused_reason":   config.PausedReason,
			"next_run_at":     config.NextRunAt,
			"last_success_at": config.LastSuccessAt,
			"updated_at":      time.Now().UTC(),
		})
	if result.Error != nil {
		return status.Errorf(status.Internal, "failed to update local LDAP sync runtime state")
	}
	if result.RowsAffected != 1 {
		return status.Errorf(status.NotFound, "local LDAP sync config not found")
	}
	return nil
}

func (s *SqlStore) CreateLDAPSyncRun(ctx context.Context, run *ldapsyncmodel.Run) error {
	if err := s.db.WithContext(ctx).Create(run).Error; err != nil {
		log.WithContext(ctx).WithError(err).Warn("failed to create local LDAP sync run")
		message := strings.ToLower(err.Error())
		if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(message, "duplicate key") || strings.Contains(message, "unique constraint") {
			return status.Errorf(status.AlreadyExists, "sync_already_running")
		}
		return status.Errorf(status.Internal, "failed to create local LDAP sync run")
	}
	return nil
}

func (s *SqlStore) GetLDAPSyncRun(ctx context.Context, accountID, connectorID, runID string) (*ldapsyncmodel.Run, error) {
	var run ldapsyncmodel.Run
	err := s.db.WithContext(ctx).
		Where("account_id = ? AND connector_id = ? AND id = ?", accountID, connectorID, runID).
		Take(&run).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Errorf(status.NotFound, "local LDAP sync run not found")
	}
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to get local LDAP sync run")
	}
	return &run, nil
}

func (s *SqlStore) CancelLDAPSyncRun(ctx context.Context, accountID, connectorID, runID string, finishedAt time.Time) (*ldapsyncmodel.Run, error) {
	result := s.db.WithContext(ctx).
		Model(&ldapsyncmodel.Run{}).
		Where(
			"id = ? AND account_id = ? AND connector_id = ? AND status IN ?",
			runID,
			accountID,
			connectorID,
			[]string{ldapsyncmodel.RunStatusQueued, ldapsyncmodel.RunStatusAwaitingApproval},
		).
		Updates(map[string]any{
			"status":        ldapsyncmodel.RunStatusCancelled,
			"finished_at":   finishedAt,
			"lease_until":   nil,
			"lease_owner":   "",
			"error_code":    "",
			"error_summary": "",
			"updated_at":    finishedAt,
		})
	if result.Error != nil {
		return nil, status.Errorf(status.Internal, "failed to cancel local LDAP sync run")
	}
	if result.RowsAffected != 1 {
		if _, err := s.GetLDAPSyncRun(ctx, accountID, connectorID, runID); err != nil {
			return nil, err
		}
		return nil, status.Errorf(status.PreconditionFailed, "only queued or awaiting-approval sync runs can be cancelled")
	}
	return s.GetLDAPSyncRun(ctx, accountID, connectorID, runID)
}

func (s *SqlStore) ListLDAPSyncRuns(ctx context.Context, accountID, connectorID string, offset, limit int) ([]*ldapsyncmodel.Run, int64, error) {
	query := s.db.WithContext(ctx).Model(&ldapsyncmodel.Run{}).
		Where("account_id = ? AND connector_id = ?", accountID, connectorID)
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, status.Errorf(status.Internal, "failed to count local LDAP sync runs")
	}
	var runs []*ldapsyncmodel.Run
	if err := query.Order("created_at DESC").Offset(offset).Limit(limit).Find(&runs).Error; err != nil {
		return nil, 0, status.Errorf(status.Internal, "failed to list local LDAP sync runs")
	}
	return runs, total, nil
}

func (s *SqlStore) CountLDAPSyncRuns(ctx context.Context, statuses ...string) (int64, error) {
	query := s.db.WithContext(ctx).Model(&ldapsyncmodel.Run{})
	if len(statuses) > 0 {
		query = query.Where("status IN ?", statuses)
	}
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return 0, status.Errorf(status.Internal, "failed to count local LDAP sync runs")
	}
	return count, nil
}

func (s *SqlStore) ClaimLDAPSyncRun(ctx context.Context, now time.Time, leaseDuration time.Duration, leaseOwner string) (*ldapsyncmodel.Run, error) {
	if strings.TrimSpace(leaseOwner) == "" {
		return nil, status.Errorf(status.InvalidArgument, "local LDAP sync lease owner is required")
	}
	var claimed *ldapsyncmodel.Run
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		query := tx.Where(
			"status = ? OR (status = ? AND lease_until < ?)",
			ldapsyncmodel.RunStatusQueued,
			ldapsyncmodel.RunStatusRunning,
			now,
		).Order("queued_at ASC")
		if s.storeEngine == "postgres" {
			query = query.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"})
		}
		var run ldapsyncmodel.Run
		if err := query.Take(&run).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		} else if err != nil {
			return err
		}

		leaseUntil := now.Add(leaseDuration)
		updates := map[string]any{
			"status":      ldapsyncmodel.RunStatusRunning,
			"lease_until": leaseUntil,
			"lease_owner": leaseOwner,
			"attempt":     run.Attempt + 1,
			"updated_at":  now,
		}
		if run.StartedAt == nil {
			updates["started_at"] = now
			run.StartedAt = &now
		}
		if err := tx.Model(&run).Updates(updates).Error; err != nil {
			return err
		}
		run.Status = ldapsyncmodel.RunStatusRunning
		run.LeaseUntil = &leaseUntil
		run.LeaseOwner = leaseOwner
		run.Attempt++
		claimed = &run
		return nil
	})
	if err != nil {
		log.WithContext(ctx).WithError(err).Error("failed to claim local LDAP sync run")
		return nil, status.Errorf(status.Internal, "failed to claim local LDAP sync run")
	}
	return claimed, nil
}

func (s *SqlStore) RenewLDAPSyncRunLease(ctx context.Context, accountID, connectorID, runID, leaseOwner string, now time.Time, leaseDuration time.Duration) (bool, error) {
	if strings.TrimSpace(leaseOwner) == "" {
		return false, status.Errorf(status.InvalidArgument, "local LDAP sync lease owner is required")
	}
	leaseUntil := now.Add(leaseDuration)
	result := s.db.WithContext(ctx).
		Model(&ldapsyncmodel.Run{}).
		Where(
			"id = ? AND account_id = ? AND connector_id = ? AND status = ? AND lease_owner = ?",
			runID, accountID, connectorID, ldapsyncmodel.RunStatusRunning, leaseOwner,
		).
		Updates(map[string]any{"lease_until": leaseUntil, "updated_at": now})
	if result.Error != nil {
		return false, status.Errorf(status.Internal, "failed to renew local LDAP sync run lease")
	}
	return result.RowsAffected == 1, nil
}

func (s *SqlStore) UpdateLDAPSyncRun(ctx context.Context, run *ldapsyncmodel.Run) error {
	result := s.db.WithContext(ctx).
		Model(&ldapsyncmodel.Run{}).
		Where("id = ? AND account_id = ? AND connector_id = ?", run.ID, run.AccountID, run.ConnectorID).
		Select("*").Omit("id", "account_id", "connector_id", "created_at").Updates(run)
	if result.Error != nil {
		return status.Errorf(status.Internal, "failed to update local LDAP sync run")
	}
	if result.RowsAffected != 1 {
		return status.Errorf(status.NotFound, "local LDAP sync run not found")
	}
	return nil
}

// UpdateLDAPSyncRunOwned only permits the worker that currently owns the lease
// to transition or finalize the run. A reclaimed stale worker therefore cannot
// overwrite the new worker's state.
func (s *SqlStore) UpdateLDAPSyncRunOwned(ctx context.Context, run *ldapsyncmodel.Run, leaseOwner string) (bool, error) {
	if strings.TrimSpace(leaseOwner) == "" {
		return false, status.Errorf(status.InvalidArgument, "local LDAP sync lease owner is required")
	}
	result := s.db.WithContext(ctx).
		Model(&ldapsyncmodel.Run{}).
		Where(
			"id = ? AND account_id = ? AND connector_id = ? AND status = ? AND lease_owner = ?",
			run.ID, run.AccountID, run.ConnectorID, ldapsyncmodel.RunStatusRunning, leaseOwner,
		).
		Select("*").Omit("id", "account_id", "connector_id", "created_at").Updates(run)
	if result.Error != nil {
		return false, status.Errorf(status.Internal, "failed to update owned local LDAP sync run")
	}
	return result.RowsAffected == 1, nil
}

func (s *SqlStore) GetLDAPSyncObjects(ctx context.Context, accountID, connectorID, objectType string) ([]*ldapsyncmodel.Object, error) {
	var objects []*ldapsyncmodel.Object
	if err := s.db.WithContext(ctx).
		Where("account_id = ? AND connector_id = ? AND object_type = ?", accountID, connectorID, objectType).
		Find(&objects).Error; err != nil {
		return nil, status.Errorf(status.Internal, "failed to list local LDAP sync objects")
	}
	return objects, nil
}

func (s *SqlStore) SaveLDAPSyncObjects(ctx context.Context, objects []*ldapsyncmodel.Object) error {
	if len(objects) == 0 {
		return nil
	}
	return s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "account_id"}, {Name: "connector_id"}, {Name: "object_type"}, {Name: "external_id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"netbird_object_id", "source_fingerprint", "last_seen_at", "managed_fields", "status", "updated_at",
		}),
	}).Create(&objects).Error
}
