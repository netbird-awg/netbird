package eventstreaming

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	eventmodel "github.com/netbirdio/netbird/management/server/localintegrations/eventstreaming/model"
)

func TestRepositoryPostgresOutboxLifecycle(t *testing.T) {
	dsn := os.Getenv("EVENT_STREAMING_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("EVENT_STREAMING_TEST_POSTGRES_DSN is not configured")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Migrator().DropTable(&eventmodel.Outbox{}, &eventmodel.Integration{}))
	require.NoError(t, db.AutoMigrate(&eventmodel.Integration{}, &eventmodel.Outbox{}))
	t.Cleanup(func() {
		require.NoError(t, db.Migrator().DropTable(&eventmodel.Outbox{}, &eventmodel.Integration{}))
	})

	repo := &repository{db: db}
	ctx := context.Background()
	require.NoError(t, repo.ensureConstraints(ctx))
	first := &eventmodel.Integration{
		AccountID:       "account-1",
		Platform:        "datadog",
		Enabled:         true,
		EncryptedConfig: "ciphertext-1",
	}
	require.NoError(t, repo.create(ctx, first))
	second := &eventmodel.Integration{
		AccountID:       "account-1",
		Platform:        "generic_http",
		Enabled:         true,
		EncryptedConfig: "ciphertext-2",
	}
	require.NoError(t, repo.create(ctx, second))

	integrations, err := repo.list(ctx, "account-1")
	require.NoError(t, err)
	require.Len(t, integrations, 2)
	for _, integration := range integrations {
		require.Equal(t, integration.ID == second.ID, integration.Enabled)
	}
	err = db.Model(&eventmodel.Integration{}).
		Where("id = ?", first.ID).
		Update("enabled", true).Error
	require.Error(t, err, "PostgreSQL must reject two enabled streams for one account")

	queued, err := repo.enqueue(ctx, "account-1", 42, "encrypted-event")
	require.NoError(t, err)
	require.True(t, queued)
	queued, err = repo.enqueue(ctx, "account-1", 42, "encrypted-event")
	require.NoError(t, err)
	require.False(t, queued, "the integration/event unique index must deduplicate delivery")

	now := time.Now().UTC()
	item, err := repo.claim(ctx, now, time.Minute, "worker-1")
	require.NoError(t, err)
	require.NotNil(t, item)
	require.Equal(t, second.ID, item.IntegrationID)

	retryErr := retryableDeliveryError("temporary destination failure")
	require.NoError(t, repo.finish(ctx, item, "worker-1", retryErr, 8, now.Add(time.Second)))
	item, err = repo.claim(ctx, now.Add(2*time.Second), time.Minute, "worker-2")
	require.NoError(t, err)
	require.NotNil(t, item)
	require.Equal(t, 1, item.Attempts)
	require.NoError(t, repo.finish(ctx, item, "worker-2", nil, 8, now))

	var delivered eventmodel.Outbox
	require.NoError(t, db.Where("id = ?", item.ID).Take(&delivered).Error)
	require.Equal(t, eventmodel.StatusDelivered, delivered.Status)
	require.NotNil(t, delivered.DeliveredAt)
	require.NotContains(t, delivered.LastError, "temporary")
}

func TestRepositoryReclaimsExpiredProcessingLease(t *testing.T) {
	dsn := os.Getenv("EVENT_STREAMING_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("EVENT_STREAMING_TEST_POSTGRES_DSN is not configured")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Migrator().DropTable(&eventmodel.Outbox{}, &eventmodel.Integration{}))
	require.NoError(t, db.AutoMigrate(&eventmodel.Integration{}, &eventmodel.Outbox{}))
	t.Cleanup(func() {
		require.NoError(t, db.Migrator().DropTable(&eventmodel.Outbox{}, &eventmodel.Integration{}))
	})

	now := time.Now().UTC()
	expired := now.Add(-time.Minute)
	integration := &eventmodel.Integration{
		AccountID:       "account-2",
		Platform:        "generic_http",
		Enabled:         true,
		EncryptedConfig: "ciphertext",
	}
	require.NoError(t, db.Create(integration).Error)
	require.NoError(t, db.Create(&eventmodel.Outbox{
		ID:               "expired-lease",
		IntegrationID:    integration.ID,
		AccountID:        integration.AccountID,
		EventID:          1,
		EncryptedPayload: "encrypted",
		Status:           eventmodel.StatusProcessing,
		NextAttemptAt:    expired,
		LeaseOwner:       "dead-worker",
		LeaseUntil:       &expired,
		CreatedAt:        expired,
	}).Error)

	ctx := context.Background()
	item, err := (&repository{db: db}).claim(ctx, now, time.Minute, "new-worker")
	require.NoError(t, err)
	require.NotNil(t, item)
	require.Equal(t, "new-worker", item.LeaseOwner)
}
