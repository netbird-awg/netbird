package edr

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	edrmodel "github.com/netbirdio/netbird/management/server/localintegrations/edr/model"
)

func TestRepositoryPostgresLifecycle(t *testing.T) {
	dsn := os.Getenv("EDR_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("EDR_TEST_POSTGRES_DSN is not configured")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Migrator().DropTable(
		&edrmodel.Device{},
		&edrmodel.Bypass{},
		&edrmodel.Integration{},
	))
	t.Cleanup(func() {
		require.NoError(t, db.Migrator().DropTable(
			&edrmodel.Device{},
			&edrmodel.Bypass{},
			&edrmodel.Integration{},
		))
	})

	ctx := context.Background()
	repo := &repository{db: db}
	require.NoError(t, repo.migrate(ctx))
	now := time.Now().UTC()
	intune := &edrmodel.Integration{
		AccountID:       "account-1",
		Provider:        providerIntune,
		CreatedBy:       "user-1",
		Enabled:         true,
		Groups:          []string{"group-1"},
		EncryptedConfig: "ciphertext",
		NextSyncAt:      now,
	}
	require.NoError(t, repo.createIntegration(ctx, intune))
	fleet := &edrmodel.Integration{
		AccountID:       "account-1",
		Provider:        providerFleetDM,
		CreatedBy:       "user-1",
		Enabled:         true,
		Groups:          []string{"group-1"},
		EncryptedConfig: "ciphertext",
		NextSyncAt:      now,
	}
	require.NoError(t, repo.createIntegration(ctx, fleet))

	enabled, err := repo.getEnabledIntegration(ctx, "account-1")
	require.NoError(t, err)
	require.Equal(t, fleet.ID, enabled.ID)
	err = db.Model(&edrmodel.Integration{}).
		Where("id = ?", intune.ID).
		Update("enabled", true).Error
	require.Error(t, err, "PostgreSQL must enforce one enabled EDR integration per account")

	claimed, err := repo.claimDueIntegration(ctx, now.Add(time.Second), "worker-1", time.Minute)
	require.NoError(t, err)
	require.Equal(t, fleet.ID, claimed.ID)
	require.NoError(t, repo.replaceDevices(
		ctx,
		fleet.ID,
		"account-1",
		[]*edrmodel.Device{{
			ExternalID:   "device-1",
			SerialNumber: "serial-1",
			Hostname:     "host-1",
			Compliant:    false,
			Reason:       "policy failed",
		}},
		now,
		now.Add(time.Minute),
		"worker-1",
	))
	device, err := repo.findDevice(ctx, fleet.ID, "serial-1", "")
	require.NoError(t, err)
	require.NotNil(t, device)
	require.Equal(t, "policy failed", device.Reason)

	stale, err := repo.claimStaleIntegration(ctx, now, now.Add(-time.Minute))
	require.NoError(t, err)
	require.Nil(t, stale)
	require.NoError(t, db.Model(&edrmodel.Integration{}).
		Where("id = ?", fleet.ID).
		Update("last_synced_at", now.Add(-time.Hour)).Error)
	stale, err = repo.claimStaleIntegration(ctx, now, now.Add(-time.Minute))
	require.NoError(t, err)
	require.NotNil(t, stale)
	require.Equal(t, fleet.ID, stale.ID)
	stale, err = repo.claimStaleIntegration(ctx, now, now.Add(-time.Minute))
	require.NoError(t, err)
	require.Nil(t, stale, "a stale transition must only be claimed once")
	require.NoError(t, repo.replaceDevices(
		ctx,
		fleet.ID,
		"account-1",
		nil,
		now,
		now.Add(time.Minute),
		"",
	))
	var refreshed edrmodel.Integration
	require.NoError(t, db.First(&refreshed, fleet.ID).Error)
	require.Nil(t, refreshed.StaleNotifiedAt, "a successful sync must reset stale notification state")

	require.NoError(t, repo.upsertBypass(ctx, &edrmodel.Bypass{
		AccountID: "account-1",
		PeerID:    "peer-1",
		CreatedBy: "user-1",
		CreatedAt: now,
	}))
	bypassed, err := repo.hasBypass(ctx, "account-1", "peer-1")
	require.NoError(t, err)
	require.True(t, bypassed)
	require.NoError(t, repo.deleteBypass(ctx, "account-1", "peer-1"))
	bypassed, err = repo.hasBypass(ctx, "account-1", "peer-1")
	require.NoError(t, err)
	require.False(t, bypassed)

	rollback := errors.New("rollback outer transaction")
	err = db.Transaction(func(tx *gorm.DB) error {
		transactionRepository := &repository{db: tx}
		require.NoError(t, transactionRepository.createIntegration(ctx, &edrmodel.Integration{
			AccountID:       "account-rollback",
			Provider:        providerIntune,
			CreatedBy:       "user-1",
			Enabled:         true,
			Groups:          []string{"group-1"},
			EncryptedConfig: "ciphertext",
			NextSyncAt:      now,
		}))
		return rollback
	})
	require.ErrorIs(t, err, rollback)
	var count int64
	require.NoError(t, db.Model(&edrmodel.Integration{}).
		Where("account_id = ?", "account-rollback").
		Count(&count).Error)
	require.Zero(t, count, "nested repository operations must participate in the outer store transaction")
}
