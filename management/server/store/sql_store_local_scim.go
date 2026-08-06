package store

import (
	"context"
	"errors"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	scimmodel "github.com/netbirdio/netbird/management/server/localintegrations/scim/model"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) ListSCIMIntegrations(ctx context.Context, accountID string) ([]*scimmodel.Integration, error) {
	var integrations []*scimmodel.Integration
	if err := s.db.WithContext(ctx).Where("account_id = ?", accountID).Order("provider ASC").Find(&integrations).Error; err != nil {
		return nil, status.Errorf(status.Internal, "failed to list SCIM integrations")
	}
	return integrations, nil
}

func (s *SqlStore) GetSCIMIntegration(ctx context.Context, accountID string, integrationID uint64) (*scimmodel.Integration, error) {
	var integration scimmodel.Integration
	err := s.db.WithContext(ctx).Where("account_id = ? AND id = ?", accountID, integrationID).Take(&integration).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Errorf(status.NotFound, "SCIM integration not found")
	}
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to get SCIM integration")
	}
	return &integration, nil
}

func (s *SqlStore) GetSCIMIntegrationByTokenHash(ctx context.Context, tokenHash string) (*scimmodel.Integration, error) {
	var integration scimmodel.Integration
	err := s.db.WithContext(ctx).Where("token_hash = ?", tokenHash).Take(&integration).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Errorf(status.NotFound, "SCIM integration not found")
	}
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to authenticate SCIM integration")
	}
	return &integration, nil
}

func (s *SqlStore) CreateSCIMIntegration(ctx context.Context, integration *scimmodel.Integration) error {
	if err := s.db.WithContext(ctx).Create(integration).Error; err != nil {
		log.WithContext(ctx).WithError(err).Warn("failed to create local SCIM integration")
		message := strings.ToLower(err.Error())
		if errors.Is(err, gorm.ErrDuplicatedKey) ||
			strings.Contains(message, "duplicate key") ||
			strings.Contains(message, "unique constraint") {
			return status.Errorf(status.AlreadyExists, "SCIM provider integration already exists")
		}
		return status.Errorf(status.Internal, "failed to create SCIM integration")
	}
	return nil
}

func (s *SqlStore) UpdateSCIMIntegration(ctx context.Context, integration *scimmodel.Integration) error {
	now := time.Now().UTC()
	updates := map[string]any{
		"provider":            integration.Provider,
		"prefix":              integration.Prefix,
		"enabled":             integration.Enabled,
		"group_prefixes":      integration.GroupPrefixes,
		"user_group_prefixes": integration.UserGroupPrefixes,
		"connector_id":        integration.ConnectorID,
		"updated_at":          now,
	}
	if integration.Enabled {
		updates["pending_at"] = now
		updates["next_attempt_at"] = now
		updates["sync_revision"] = gorm.Expr("sync_revision + 1")
	} else {
		updates["lease_until"] = nil
		updates["lease_owner"] = ""
	}
	result := s.db.WithContext(ctx).Model(&scimmodel.Integration{}).
		Where("account_id = ? AND id = ?", integration.AccountID, integration.ID).
		Updates(updates)
	if result.Error != nil {
		return status.Errorf(status.Internal, "failed to update SCIM integration")
	}
	if result.RowsAffected != 1 {
		return status.Errorf(status.NotFound, "SCIM integration not found")
	}
	return nil
}

func (s *SqlStore) DeleteSCIMIntegration(ctx context.Context, accountID string, integrationID uint64) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var integration scimmodel.Integration
		if err := tx.Where("account_id = ? AND id = ?", accountID, integrationID).Take(&integration).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return status.Errorf(status.NotFound, "SCIM integration not found")
			}
			return status.Errorf(status.Internal, "failed to get SCIM integration")
		}
		if err := tx.Where("integration_id = ?", integrationID).Delete(&scimmodel.Resource{}).Error; err != nil {
			return status.Errorf(status.Internal, "failed to delete SCIM resources")
		}
		if err := tx.Where("integration_id = ?", integrationID).Delete(&scimmodel.SyncLog{}).Error; err != nil {
			return status.Errorf(status.Internal, "failed to delete SCIM logs")
		}
		if err := tx.Delete(&integration).Error; err != nil {
			return status.Errorf(status.Internal, "failed to delete SCIM integration")
		}
		return nil
	})
}

func (s *SqlStore) RotateSCIMIntegrationToken(
	ctx context.Context,
	accountID string,
	integrationID uint64,
	tokenHash, tokenHint string,
) error {
	result := s.db.WithContext(ctx).Model(&scimmodel.Integration{}).
		Where("account_id = ? AND id = ?", accountID, integrationID).
		Updates(map[string]any{
			"token_hash": tokenHash,
			"token_hint": tokenHint,
			"updated_at": time.Now().UTC(),
		})
	if result.Error != nil {
		return status.Errorf(status.Internal, "failed to rotate SCIM token")
	}
	if result.RowsAffected != 1 {
		return status.Errorf(status.NotFound, "SCIM integration not found")
	}
	return nil
}

func (s *SqlStore) ListSCIMLogs(
	ctx context.Context,
	accountID string,
	integrationID uint64,
	limit int,
) ([]*scimmodel.SyncLog, error) {
	if _, err := s.GetSCIMIntegration(ctx, accountID, integrationID); err != nil {
		return nil, err
	}
	var logs []*scimmodel.SyncLog
	if err := s.db.WithContext(ctx).
		Where("integration_id = ?", integrationID).
		Order("created_at DESC").
		Limit(limit).
		Find(&logs).Error; err != nil {
		return nil, status.Errorf(status.Internal, "failed to list SCIM synchronization logs")
	}
	return logs, nil
}

func (s *SqlStore) AddSCIMLog(ctx context.Context, entry *scimmodel.SyncLog) error {
	if err := s.db.WithContext(ctx).Create(entry).Error; err != nil {
		return status.Errorf(status.Internal, "failed to store SCIM synchronization log")
	}
	subquery := s.db.Model(&scimmodel.SyncLog{}).
		Select("id").
		Where("integration_id = ?", entry.IntegrationID).
		Order("created_at DESC").
		Limit(500)
	if err := s.db.WithContext(ctx).
		Where("integration_id = ? AND id NOT IN (?)", entry.IntegrationID, subquery).
		Delete(&scimmodel.SyncLog{}).Error; err != nil {
		log.WithContext(ctx).WithError(err).Debug("failed to prune old local SCIM logs")
	}
	return nil
}

func (s *SqlStore) GetSCIMResource(
	ctx context.Context,
	integrationID uint64,
	resourceType, resourceID string,
) (*scimmodel.Resource, error) {
	var resource scimmodel.Resource
	err := s.db.WithContext(ctx).
		Where(
			"integration_id = ? AND resource_type = ? AND id = ? AND deleted = ?",
			integrationID, resourceType, resourceID, false,
		).
		Take(&resource).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Errorf(status.NotFound, "SCIM resource not found")
	}
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to get SCIM resource")
	}
	return &resource, nil
}

func (s *SqlStore) FindSCIMResources(
	ctx context.Context,
	integrationID uint64,
	resourceType, lookupColumn, lookupHash string,
) ([]*scimmodel.Resource, error) {
	if lookupColumn != "external_id_hash" && lookupColumn != "user_name_hash" {
		return nil, status.Errorf(status.InvalidArgument, "unsupported SCIM lookup")
	}
	var resources []*scimmodel.Resource
	if err := s.db.WithContext(ctx).
		Where(
			"integration_id = ? AND resource_type = ? AND deleted = ? AND "+lookupColumn+" = ?",
			integrationID, resourceType, false, lookupHash,
		).
		Order("created_at ASC").
		Find(&resources).Error; err != nil {
		return nil, status.Errorf(status.Internal, "failed to find SCIM resources")
	}
	return resources, nil
}

func (s *SqlStore) ListSCIMResources(
	ctx context.Context,
	integrationID uint64,
	resourceType string,
	includeDeleted bool,
) ([]*scimmodel.Resource, error) {
	query := s.db.WithContext(ctx).Where("integration_id = ? AND resource_type = ?", integrationID, resourceType)
	if !includeDeleted {
		query = query.Where("deleted = ?", false)
	}
	var resources []*scimmodel.Resource
	if err := query.Order("created_at ASC").Find(&resources).Error; err != nil {
		return nil, status.Errorf(status.Internal, "failed to list SCIM resources")
	}
	return resources, nil
}

func (s *SqlStore) SaveSCIMResourceAndQueue(
	ctx context.Context,
	resource *scimmodel.Resource,
	queuedAt time.Time,
) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"external_id_hash", "user_name_hash", "encrypted_payload",
				"deleted", "source_fingerprint", "updated_at",
			}),
		}).Create(resource).Error; err != nil {
			return status.Errorf(status.Internal, "failed to store SCIM resource")
		}
		return queueSCIMIntegration(tx, resource.IntegrationID, queuedAt)
	})
}

func (s *SqlStore) DeleteSCIMResourceAndQueue(
	ctx context.Context,
	integrationID uint64,
	resourceType, resourceID string,
	queuedAt time.Time,
) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&scimmodel.Resource{}).
			Where(
				"integration_id = ? AND resource_type = ? AND id = ? AND deleted = ?",
				integrationID, resourceType, resourceID, false,
			).
			Updates(map[string]any{"deleted": true, "updated_at": queuedAt})
		if result.Error != nil {
			return status.Errorf(status.Internal, "failed to delete SCIM resource")
		}
		if result.RowsAffected != 1 {
			return status.Errorf(status.NotFound, "SCIM resource not found")
		}
		return queueSCIMIntegration(tx, integrationID, queuedAt)
	})
}

func queueSCIMIntegration(tx *gorm.DB, integrationID uint64, queuedAt time.Time) error {
	result := tx.Model(&scimmodel.Integration{}).
		Where("id = ? AND enabled = ?", integrationID, true).
		Updates(map[string]any{
			"pending_at":      queuedAt,
			"next_attempt_at": queuedAt,
			"sync_revision":   gorm.Expr("sync_revision + 1"),
			"updated_at":      queuedAt,
		})
	if result.Error != nil {
		return status.Errorf(status.Internal, "failed to queue SCIM synchronization")
	}
	if result.RowsAffected != 1 {
		return status.Errorf(status.PreconditionFailed, "SCIM integration is disabled or unavailable")
	}
	return nil
}

func (s *SqlStore) UpdateSCIMResourceTarget(
	ctx context.Context,
	integrationID uint64,
	resourceType, resourceID, netBirdObjectID string,
) error {
	result := s.db.WithContext(ctx).Model(&scimmodel.Resource{}).
		Where("integration_id = ? AND resource_type = ? AND id = ?", integrationID, resourceType, resourceID).
		Updates(map[string]any{
			"net_bird_object_id": netBirdObjectID,
			"updated_at":         time.Now().UTC(),
		})
	if result.Error != nil {
		return status.Errorf(status.Internal, "failed to update SCIM target mapping")
	}
	if result.RowsAffected != 1 {
		return status.Errorf(status.NotFound, "SCIM resource not found")
	}
	return nil
}

func (s *SqlStore) ClaimSCIMIntegration(
	ctx context.Context,
	now time.Time,
	leaseDuration time.Duration,
	leaseOwner string,
) (*scimmodel.Integration, error) {
	if strings.TrimSpace(leaseOwner) == "" {
		return nil, status.Errorf(status.InvalidArgument, "SCIM synchronization lease owner is required")
	}
	var claimed *scimmodel.Integration
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		query := tx.Where(
			"enabled = ? AND pending_at IS NOT NULL AND (next_attempt_at IS NULL OR next_attempt_at <= ?) "+
				"AND (lease_until IS NULL OR lease_until < ?)",
			true, now, now,
		).Order("pending_at ASC")
		if s.storeEngine == "postgres" {
			query = query.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"})
		}
		var integration scimmodel.Integration
		if err := query.Take(&integration).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		leaseUntil := now.Add(leaseDuration)
		if err := tx.Model(&integration).Updates(map[string]any{
			"lease_until": leaseUntil,
			"lease_owner": leaseOwner,
			"updated_at":  now,
		}).Error; err != nil {
			return err
		}
		integration.LeaseUntil = &leaseUntil
		integration.LeaseOwner = leaseOwner
		claimed = &integration
		return nil
	})
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to claim SCIM synchronization")
	}
	return claimed, nil
}

func (s *SqlStore) RenewSCIMIntegrationLease(
	ctx context.Context,
	integrationID uint64,
	leaseOwner string,
	now time.Time,
	leaseDuration time.Duration,
) (bool, error) {
	if strings.TrimSpace(leaseOwner) == "" {
		return false, status.Errorf(status.InvalidArgument, "SCIM synchronization lease owner is required")
	}
	result := s.db.WithContext(ctx).Model(&scimmodel.Integration{}).
		Where("id = ? AND lease_owner = ?", integrationID, leaseOwner).
		Updates(map[string]any{
			"lease_until": now.Add(leaseDuration),
			"updated_at":  now,
		})
	if result.Error != nil {
		return false, status.Errorf(status.Internal, "failed to renew SCIM synchronization lease")
	}
	return result.RowsAffected == 1, nil
}

func (s *SqlStore) FinishSCIMIntegrationSync(
	ctx context.Context,
	integrationID uint64,
	leaseOwner string,
	claimedRevision int64,
	result scimmodel.SyncResult,
) (bool, error) {
	updates := map[string]any{
		"lease_until": nil,
		"lease_owner": "",
		"updated_at":  result.SyncedAt,
	}
	if result.Succeeded {
		updates["last_synced_at"] = result.SyncedAt
		updates["failure_count"] = 0
		updates["next_attempt_at"] = nil
		updates["pending_at"] = gorm.Expr(
			"CASE WHEN sync_revision = ? THEN NULL ELSE pending_at END", claimedRevision,
		)
	} else {
		updates["failure_count"] = gorm.Expr("failure_count + 1")
		updates["next_attempt_at"] = result.NextAttemptAt
	}
	dbResult := s.db.WithContext(ctx).Model(&scimmodel.Integration{}).
		Where("id = ? AND lease_owner = ?", integrationID, leaseOwner).
		Updates(updates)
	if dbResult.Error != nil {
		return false, status.Errorf(status.Internal, "failed to finalize SCIM synchronization")
	}
	return dbResult.RowsAffected == 1, nil
}
