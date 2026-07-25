package edr

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	edrmodel "github.com/netbirdio/netbird/management/server/localintegrations/edr/model"
	"github.com/netbirdio/netbird/shared/management/status"
)

type repository struct {
	db *gorm.DB
}

func (r *repository) migrate(ctx context.Context) error {
	if err := r.db.WithContext(ctx).AutoMigrate(
		&edrmodel.Integration{},
		&edrmodel.Device{},
		&edrmodel.Bypass{},
	); err != nil {
		return fmt.Errorf("migrate local EDR tables: %w", err)
	}
	const oneEnabled = `
		CREATE UNIQUE INDEX IF NOT EXISTS idx_local_edr_one_enabled
		ON local_edr_integrations (account_id)
		WHERE enabled = TRUE`
	if err := r.db.WithContext(ctx).Exec(oneEnabled).Error; err != nil {
		return fmt.Errorf("create local EDR enabled constraint: %w", err)
	}
	return nil
}

func (r *repository) getIntegration(
	ctx context.Context,
	accountID, provider string,
) (*edrmodel.Integration, error) {
	return r.getIntegrationWithLock(ctx, accountID, provider, false)
}

func (r *repository) getIntegrationForUpdate(
	ctx context.Context,
	accountID, provider string,
) (*edrmodel.Integration, error) {
	return r.getIntegrationWithLock(ctx, accountID, provider, true)
}

func (r *repository) getIntegrationWithLock(
	ctx context.Context,
	accountID, provider string,
	lock bool,
) (*edrmodel.Integration, error) {
	var integration edrmodel.Integration
	query := r.db.WithContext(ctx)
	if lock {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	err := query.Where("account_id = ? AND provider = ?", accountID, provider).
		Take(&integration).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Errorf(status.NotFound, "%s EDR integration not found", provider)
	}
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to get EDR integration")
	}
	return &integration, nil
}

func (r *repository) getEnabledIntegration(
	ctx context.Context,
	accountID string,
) (*edrmodel.Integration, error) {
	var integration edrmodel.Integration
	err := r.db.WithContext(ctx).
		Where("account_id = ? AND enabled = ?", accountID, true).
		Take(&integration).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to get enabled EDR integration")
	}
	return &integration, nil
}

func (r *repository) createIntegration(
	ctx context.Context,
	integration *edrmodel.Integration,
) error {
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if integration.Enabled {
			if err := disableOtherIntegrations(tx, integration.AccountID, integration.Provider); err != nil {
				return err
			}
		}
		return tx.Create(integration).Error
	})
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if errors.Is(err, gorm.ErrDuplicatedKey) ||
		strings.Contains(message, "duplicate key") ||
		strings.Contains(message, "unique constraint") {
		return status.Errorf(status.AlreadyExists, "%s EDR integration already exists", integration.Provider)
	}
	return status.Errorf(status.Internal, "failed to create EDR integration")
}

func (r *repository) updateIntegration(
	ctx context.Context,
	integration *edrmodel.Integration,
) error {
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if integration.Enabled {
			if err := disableOtherIntegrations(tx, integration.AccountID, integration.Provider); err != nil {
				return err
			}
		}
		result := tx.Model(&edrmodel.Integration{}).
			Where("account_id = ? AND provider = ?", integration.AccountID, integration.Provider).
			Updates(map[string]any{
				"enabled":           integration.Enabled,
				"groups":            integration.Groups,
				"encrypted_config":  integration.EncryptedConfig,
				"last_synced_at":    nil,
				"stale_notified_at": nil,
				"next_sync_at":      integration.NextSyncAt,
				"failure_count":     0,
				"last_error":        "",
				"lease_owner":       "",
				"lease_until":       nil,
				"updated_at":        time.Now().UTC(),
			})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return status.Errorf(status.NotFound, "%s EDR integration not found", integration.Provider)
	}
	if err != nil {
		return status.Errorf(status.Internal, "failed to update EDR integration")
	}
	return nil
}

func disableOtherIntegrations(tx *gorm.DB, accountID, exceptProvider string) error {
	return tx.Model(&edrmodel.Integration{}).
		Where("account_id = ? AND provider <> ? AND enabled = ?", accountID, exceptProvider, true).
		Updates(map[string]any{
			"enabled":       false,
			"lease_owner":   "",
			"lease_until":   nil,
			"failure_count": 0,
		}).Error
}

func (r *repository) deleteIntegration(ctx context.Context, accountID, provider string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var integration edrmodel.Integration
		err := tx.Where("account_id = ? AND provider = ?", accountID, provider).
			Take(&integration).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return status.Errorf(status.NotFound, "%s EDR integration not found", provider)
		}
		if err != nil {
			return status.Errorf(status.Internal, "failed to get EDR integration")
		}
		if err := tx.Where("integration_id = ?", integration.ID).
			Delete(&edrmodel.Device{}).Error; err != nil {
			return status.Errorf(status.Internal, "failed to delete EDR devices")
		}
		if err := tx.Delete(&integration).Error; err != nil {
			return status.Errorf(status.Internal, "failed to delete EDR integration")
		}
		return nil
	})
}

func (r *repository) replaceDevices(
	ctx context.Context,
	integrationID uint64,
	accountID string,
	devices []*edrmodel.Device,
	syncedAt time.Time,
	nextSyncAt time.Time,
	leaseOwner string,
) error {
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("integration_id = ?", integrationID).
			Delete(&edrmodel.Device{}).Error; err != nil {
			return err
		}
		if len(devices) > 0 {
			for _, device := range devices {
				device.IntegrationID = integrationID
				device.AccountID = accountID
				device.SyncedAt = syncedAt
			}
			if err := tx.CreateInBatches(devices, 500).Error; err != nil {
				return err
			}
		}
		query := tx.Model(&edrmodel.Integration{}).Where("id = ?", integrationID)
		if leaseOwner != "" {
			query = query.Where("lease_owner = ?", leaseOwner)
		}
		result := query.
			Updates(map[string]any{
				"last_synced_at":    syncedAt,
				"stale_notified_at": nil,
				"next_sync_at":      nextSyncAt,
				"failure_count":     0,
				"last_error":        "",
				"lease_owner":       "",
				"lease_until":       nil,
				"updated_at":        syncedAt,
			})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
	if err != nil {
		return status.Errorf(status.Internal, "failed to store EDR device snapshot")
	}
	return nil
}

func (r *repository) markSyncFailure(
	ctx context.Context,
	integrationID uint64,
	nextSyncAt time.Time,
	message string,
	leaseOwner string,
) error {
	if len(message) > 512 {
		message = message[:512]
	}
	query := r.db.WithContext(ctx).Model(&edrmodel.Integration{}).Where("id = ?", integrationID)
	if leaseOwner != "" {
		query = query.Where("lease_owner = ?", leaseOwner)
	}
	result := query.
		Updates(map[string]any{
			"next_sync_at":  nextSyncAt,
			"failure_count": gorm.Expr("failure_count + 1"),
			"last_error":    message,
			"lease_owner":   "",
			"lease_until":   nil,
			"updated_at":    time.Now().UTC(),
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func (r *repository) claimDueIntegration(
	ctx context.Context,
	now time.Time,
	owner string,
	leaseDuration time.Duration,
) (*edrmodel.Integration, error) {
	var claimed *edrmodel.Integration
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var integration edrmodel.Integration
		err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where(
				"enabled = ? AND next_sync_at <= ? AND (lease_until IS NULL OR lease_until < ?)",
				true, now, now,
			).
			Order("next_sync_at ASC").
			Take(&integration).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		leaseUntil := now.Add(leaseDuration)
		result := tx.Model(&edrmodel.Integration{}).
			Where("id = ? AND enabled = ?", integration.ID, true).
			Updates(map[string]any{
				"lease_owner": owner,
				"lease_until": leaseUntil,
			})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return nil
		}
		integration.LeaseOwner = owner
		integration.LeaseUntil = &leaseUntil
		claimed = &integration
		return nil
	})
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to claim EDR synchronization")
	}
	return claimed, nil
}

func (r *repository) claimStaleIntegration(
	ctx context.Context,
	now time.Time,
	staleBefore time.Time,
) (*edrmodel.Integration, error) {
	var claimed *edrmodel.Integration
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var integration edrmodel.Integration
		err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where(
				"enabled = ? AND stale_notified_at IS NULL AND (last_synced_at IS NULL OR last_synced_at <= ?)",
				true,
				staleBefore,
			).
			Order("last_synced_at ASC NULLS FIRST").
			Take(&integration).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		result := tx.Model(&edrmodel.Integration{}).
			Where("id = ? AND enabled = ? AND stale_notified_at IS NULL", integration.ID, true).
			Update("stale_notified_at", now)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return nil
		}
		integration.StaleNotifiedAt = &now
		claimed = &integration
		return nil
	})
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to claim stale EDR snapshot")
	}
	return claimed, nil
}

func (r *repository) findDevice(
	ctx context.Context,
	integrationID uint64,
	serialNumber, hostname string,
) (*edrmodel.Device, error) {
	query := r.db.WithContext(ctx).Where("integration_id = ?", integrationID)
	if serialNumber != "" {
		var devices []edrmodel.Device
		err := query.Where("serial_number = ?", serialNumber).Order("id ASC").Limit(2).Find(&devices).Error
		if err != nil {
			return nil, status.Errorf(status.Internal, "failed to find EDR device")
		}
		if len(devices) == 1 {
			return &devices[0], nil
		}
		if len(devices) > 1 {
			return nil, nil
		}
	}
	if hostname == "" {
		return nil, nil
	}
	var devices []edrmodel.Device
	err := query.Where("hostname = ?", hostname).Order("id ASC").Limit(2).Find(&devices).Error
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to find EDR device")
	}
	if len(devices) != 1 {
		return nil, nil
	}
	return &devices[0], nil
}

func (r *repository) listDevices(
	ctx context.Context,
	integrationID uint64,
) ([]edrmodel.Device, error) {
	var devices []edrmodel.Device
	if err := r.db.WithContext(ctx).
		Where("integration_id = ?", integrationID).
		Find(&devices).Error; err != nil {
		return nil, status.Errorf(status.Internal, "failed to list EDR devices")
	}
	return devices, nil
}

func (r *repository) upsertBypass(ctx context.Context, bypass *edrmodel.Bypass) error {
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "account_id"}, {Name: "peer_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"created_by", "created_at"}),
		}).
		Create(bypass).Error
}

func (r *repository) deleteBypass(ctx context.Context, accountID, peerID string) error {
	return r.db.WithContext(ctx).
		Where("account_id = ? AND peer_id = ?", accountID, peerID).
		Delete(&edrmodel.Bypass{}).Error
}

func (r *repository) deleteAccountBypasses(ctx context.Context, accountID string) error {
	return r.db.WithContext(ctx).
		Where("account_id = ?", accountID).
		Delete(&edrmodel.Bypass{}).Error
}

func (r *repository) hasBypass(ctx context.Context, accountID, peerID string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&edrmodel.Bypass{}).
		Where("account_id = ? AND peer_id = ?", accountID, peerID).
		Count(&count).Error
	return count > 0, err
}

func (r *repository) listBypasses(ctx context.Context, accountID string) ([]edrmodel.Bypass, error) {
	var bypasses []edrmodel.Bypass
	err := r.db.WithContext(ctx).
		Where("account_id = ?", accountID).
		Order("created_at ASC").
		Find(&bypasses).Error
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to list EDR bypasses")
	}
	return bypasses, nil
}
