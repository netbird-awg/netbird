package eventstreaming

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rs/xid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	eventmodel "github.com/netbirdio/netbird/management/server/localintegrations/eventstreaming/model"
	"github.com/netbirdio/netbird/shared/management/status"
)

type repository struct {
	db *gorm.DB
}

const maxPendingOutboxPerIntegration int64 = 100_000

func (r *repository) ensureConstraints(ctx context.Context) error {
	const oneEnabledPerAccount = `
		CREATE UNIQUE INDEX IF NOT EXISTS idx_local_event_stream_one_enabled
		ON local_event_stream_integrations (account_id)
		WHERE enabled = TRUE`
	if err := r.db.WithContext(ctx).Exec(oneEnabledPerAccount).Error; err != nil {
		return fmt.Errorf("create event streaming account constraint: %w", err)
	}
	return nil
}

func (r *repository) list(ctx context.Context, accountID string) ([]*eventmodel.Integration, error) {
	var integrations []*eventmodel.Integration
	err := r.db.WithContext(ctx).
		Where("account_id = ?", accountID).
		Order("platform ASC").
		Find(&integrations).Error
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to list event streaming integrations")
	}
	return integrations, nil
}

func (r *repository) get(ctx context.Context, accountID string, id uint64) (*eventmodel.Integration, error) {
	var integration eventmodel.Integration
	err := r.db.WithContext(ctx).
		Where("account_id = ? AND id = ?", accountID, id).
		Take(&integration).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Errorf(status.NotFound, "event streaming integration not found")
	}
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to get event streaming integration")
	}
	return &integration, nil
}

func (r *repository) create(ctx context.Context, integration *eventmodel.Integration) error {
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if integration.Enabled {
			if err := disableOtherIntegrations(tx, integration.AccountID, 0); err != nil {
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
		return status.Errorf(status.AlreadyExists, "event streaming platform integration already exists")
	}
	return status.Errorf(status.Internal, "failed to create event streaming integration")
}

func (r *repository) update(ctx context.Context, integration *eventmodel.Integration) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if integration.Enabled {
			if err := disableOtherIntegrations(tx, integration.AccountID, integration.ID); err != nil {
				return err
			}
		}
		result := tx.Model(&eventmodel.Integration{}).
			Where("account_id = ? AND id = ?", integration.AccountID, integration.ID).
			Updates(map[string]any{
				"enabled":          integration.Enabled,
				"encrypted_config": integration.EncryptedConfig,
				"updated_at":       time.Now().UTC(),
			})
		if result.Error != nil {
			return status.Errorf(status.Internal, "failed to update event streaming integration")
		}
		if result.RowsAffected != 1 {
			return status.Errorf(status.NotFound, "event streaming integration not found")
		}
		if !integration.Enabled {
			if err := tx.Model(&eventmodel.Outbox{}).
				Where("integration_id = ? AND status IN ?", integration.ID, []string{
					eventmodel.StatusPending, eventmodel.StatusProcessing,
				}).
				Updates(map[string]any{
					"status":      eventmodel.StatusDead,
					"lease_owner": "",
					"lease_until": nil,
					"last_error":  "integration disabled before delivery",
					"updated_at":  time.Now().UTC(),
				}).Error; err != nil {
				return status.Errorf(status.Internal, "failed to stop pending event deliveries")
			}
		}
		return nil
	})
}

func disableOtherIntegrations(tx *gorm.DB, accountID string, exceptID uint64) error {
	query := tx.Model(&eventmodel.Integration{}).
		Where("account_id = ? AND enabled = ?", accountID, true)
	if exceptID != 0 {
		query = query.Where("id <> ?", exceptID)
	}
	if err := query.Update("enabled", false).Error; err != nil {
		return status.Errorf(status.Internal, "failed to enforce one enabled event stream")
	}
	return nil
}

func (r *repository) delete(ctx context.Context, accountID string, id uint64) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var integration eventmodel.Integration
		err := tx.Where("account_id = ? AND id = ?", accountID, id).Take(&integration).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return status.Errorf(status.NotFound, "event streaming integration not found")
		}
		if err != nil {
			return status.Errorf(status.Internal, "failed to get event streaming integration")
		}
		if err := tx.Where("integration_id = ?", id).Delete(&eventmodel.Outbox{}).Error; err != nil {
			return status.Errorf(status.Internal, "failed to delete event streaming outbox")
		}
		if err := tx.Delete(&integration).Error; err != nil {
			return status.Errorf(status.Internal, "failed to delete event streaming integration")
		}
		return nil
	})
}

func (r *repository) enqueue(
	ctx context.Context,
	accountID string,
	eventID uint64,
	encryptedPayload string,
) (bool, error) {
	var queued bool
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var integration eventmodel.Integration
		err := tx.Clauses(clause.Locking{Strength: "SHARE"}).
			Where("account_id = ? AND enabled = ?", accountID, true).
			Order("id ASC").
			Take(&integration).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		var pending int64
		if err := tx.Model(&eventmodel.Outbox{}).
			Where("integration_id = ? AND status IN ?", integration.ID, []string{
				eventmodel.StatusPending, eventmodel.StatusProcessing,
			}).
			Count(&pending).Error; err != nil {
			return err
		}
		if pending >= maxPendingOutboxPerIntegration {
			return status.Errorf(status.TooManyRequests, "event streaming outbox capacity reached")
		}
		now := time.Now().UTC()
		item := &eventmodel.Outbox{
			ID:               xid.New().String(),
			IntegrationID:    integration.ID,
			AccountID:        accountID,
			EventID:          eventID,
			EncryptedPayload: encryptedPayload,
			Status:           eventmodel.StatusPending,
			NextAttemptAt:    now,
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		result := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(item)
		if result.Error != nil {
			return result.Error
		}
		queued = result.RowsAffected == 1
		return nil
	})
	if err != nil {
		return false, status.Errorf(status.Internal, "failed to queue event stream delivery")
	}
	return queued, nil
}

func (r *repository) claim(
	ctx context.Context,
	now time.Time,
	leaseDuration time.Duration,
	owner string,
) (*eventmodel.Outbox, error) {
	var claimed *eventmodel.Outbox
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var item eventmodel.Outbox
		err := tx.Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where(
				"status IN ? AND next_attempt_at <= ? AND (lease_until IS NULL OR lease_until < ?)",
				[]string{eventmodel.StatusPending, eventmodel.StatusProcessing}, now, now,
			).
			Order("next_attempt_at ASC, created_at ASC").
			Take(&item).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		leaseUntil := now.Add(leaseDuration)
		result := tx.Model(&eventmodel.Outbox{}).
			Where("id = ? AND status IN ?", item.ID, []string{
				eventmodel.StatusPending, eventmodel.StatusProcessing,
			}).
			Updates(map[string]any{
				"status":      eventmodel.StatusProcessing,
				"lease_owner": owner,
				"lease_until": leaseUntil,
				"updated_at":  now,
			})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return nil
		}
		item.Status = eventmodel.StatusProcessing
		item.LeaseOwner = owner
		item.LeaseUntil = &leaseUntil
		claimed = &item
		return nil
	})
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to claim event stream delivery")
	}
	return claimed, nil
}

//nolint:nilnil // A nil integration marks an outbox item whose integration was removed.
func (r *repository) integrationByID(ctx context.Context, id uint64) (*eventmodel.Integration, error) {
	var integration eventmodel.Integration
	err := r.db.WithContext(ctx).Where("id = ?", id).Take(&integration).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, status.Errorf(status.Internal, "failed to load event streaming integration")
	}
	return &integration, nil
}

func (r *repository) finish(
	ctx context.Context,
	item *eventmodel.Outbox,
	owner string,
	deliveryErr error,
	maxAttempts int,
	nextAttemptAt time.Time,
) error {
	now := time.Now().UTC()
	updates := map[string]any{
		"lease_owner": "",
		"lease_until": nil,
		"updated_at":  now,
	}
	if deliveryErr == nil {
		updates["status"] = eventmodel.StatusDelivered
		updates["delivered_at"] = now
		updates["last_error"] = ""
	} else {
		attempts := item.Attempts + 1
		updates["attempts"] = attempts
		updates["last_error"] = sanitizeDeliveryError(deliveryErr)
		if attempts >= maxAttempts || !isRetryable(deliveryErr) {
			updates["status"] = eventmodel.StatusDead
		} else {
			updates["status"] = eventmodel.StatusPending
			updates["next_attempt_at"] = nextAttemptAt
		}
	}
	result := r.db.WithContext(ctx).Model(&eventmodel.Outbox{}).
		Where("id = ? AND status = ? AND lease_owner = ?", item.ID, eventmodel.StatusProcessing, owner).
		Updates(updates)
	if result.Error != nil {
		return status.Errorf(status.Internal, "failed to finalize event stream delivery")
	}
	return nil
}

func (r *repository) prune(ctx context.Context, now time.Time) error {
	deliveredBefore := now.Add(-7 * 24 * time.Hour)
	deadBefore := now.Add(-30 * 24 * time.Hour)
	return r.db.WithContext(ctx).
		Where(
			"(status = ? AND delivered_at < ?) OR (status = ? AND updated_at < ?)",
			eventmodel.StatusDelivered, deliveredBefore, eventmodel.StatusDead, deadBefore,
		).
		Delete(&eventmodel.Outbox{}).Error
}
