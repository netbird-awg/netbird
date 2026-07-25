package scim

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	scimmodel "github.com/netbirdio/netbird/management/server/localintegrations/scim/model"
)

const (
	workerPollInterval = 5 * time.Second
	syncLeaseDuration  = 2 * time.Minute
	leaseRenewInterval = 30 * time.Second
	maxSyncBackoff     = 5 * time.Minute
)

func (s *Service) Start(ctx context.Context) {
	s.startOnce.Do(func() {
		if err := s.requirePostgres(); err != nil {
			log.WithContext(ctx).WithError(err).Warn("local SCIM worker is disabled")
			return
		}
		go s.runWorker(ctx)
	})
}

func (s *Service) runWorker(ctx context.Context) {
	ticker := time.NewTicker(workerPollInterval)
	defer ticker.Stop()
	for {
		if err := s.drainReadyIntegrations(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.WithContext(ctx).WithError(err).Error("local SCIM worker iteration failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.signal:
		}
	}
}

func (s *Service) drainReadyIntegrations(ctx context.Context) error {
	for {
		integration, err := s.store.ClaimSCIMIntegration(
			ctx, time.Now().UTC(), syncLeaseDuration, s.workerID,
		)
		if err != nil {
			return err
		}
		if integration == nil {
			return nil
		}
		s.executeSync(ctx, integration)
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

func (s *Service) executeSync(ctx context.Context, integration *scimmodel.Integration) {
	startedAt := time.Now().UTC()
	claimedRevision := integration.SyncRevision
	result := scimmodel.SyncResult{SyncedAt: startedAt}

	syncCtx, cancelSync := context.WithCancel(ctx)
	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	leaseLost := make(chan struct{}, 1)
	go s.renewLease(heartbeatCtx, cancelSync, integration.ID, leaseLost)

	releaseGlobalLock := s.accounts.GetStore().AcquireGlobalLock(syncCtx)
	summary, err := s.syncIntegration(syncCtx, integration)
	releaseGlobalLock()
	stopHeartbeat()
	cancelSync()
	select {
	case <-leaseLost:
		err = errors.New("SCIM synchronization lease lost")
	default:
	}

	if err == nil {
		result.Succeeded = true
		result.SyncedAt = time.Now().UTC()
		_ = s.addLog(ctx, integration.ID, "info", fmt.Sprintf(
			"synchronized %d users and %d groups; %d skipped, %d disabled",
			summary.Users, summary.Groups, summary.Skipped, summary.Disabled,
		))
	} else {
		result.ErrorSummary = sanitizeSyncError(err)
		backoff := syncBackoff(integration.FailureCount + 1)
		next := time.Now().UTC().Add(backoff)
		result.NextAttemptAt = &next
		_ = s.addLog(ctx, integration.ID, "error", "synchronization failed: "+result.ErrorSummary)
	}
	owned, finishErr := s.store.FinishSCIMIntegrationSync(
		ctx, integration.ID, s.workerID, claimedRevision, result,
	)
	if finishErr != nil {
		log.WithContext(ctx).WithError(finishErr).WithField("integration_id", integration.ID).
			Error("failed to finalize local SCIM synchronization")
		return
	}
	if !owned {
		log.WithContext(ctx).WithField("integration_id", integration.ID).
			Warn("discarded local SCIM synchronization result after lease was lost")
	}
}

func (s *Service) renewLease(
	ctx context.Context,
	cancelSync context.CancelFunc,
	integrationID uint64,
	leaseLost chan<- struct{},
) {
	ticker := time.NewTicker(leaseRenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			owned, err := s.store.RenewSCIMIntegrationLease(
				ctx, integrationID, s.workerID, now.UTC(), syncLeaseDuration,
			)
			if err == nil && owned {
				continue
			}
			select {
			case leaseLost <- struct{}{}:
			default:
			}
			cancelSync()
			return
		}
	}
}

func (s *Service) addLog(ctx context.Context, integrationID uint64, level, message string) error {
	message = strings.TrimSpace(message)
	if len(message) > 512 {
		message = message[:512]
	}
	return s.store.AddSCIMLog(ctx, &scimmodel.SyncLog{
		IntegrationID: integrationID,
		Level:         level,
		Message:       message,
		CreatedAt:     time.Now().UTC(),
	})
}

func syncBackoff(failureCount int) time.Duration {
	if failureCount < 1 {
		failureCount = 1
	}
	backoff := time.Duration(1<<min(failureCount-1, 6)) * 5 * time.Second
	return min(backoff, maxSyncBackoff)
}

func sanitizeSyncError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	replacements := []struct {
		from string
		to   string
	}{
		{"token", "credential"},
		{"password", "credential"},
		{"secret", "credential"},
	}
	lower := strings.ToLower(message)
	for _, replacement := range replacements {
		if strings.Contains(lower, replacement.from) {
			return "internal synchronization error"
		}
	}
	if len(message) > 256 {
		message = message[:256]
	}
	return message
}
