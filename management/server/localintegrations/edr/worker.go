package edr

import (
	"context"
	"fmt"
	"math"
	"time"

	log "github.com/sirupsen/logrus"

	edrmodel "github.com/netbirdio/netbird/management/server/localintegrations/edr/model"
)

const (
	workerPollInterval = 15 * time.Second
	maxRetryDelay      = time.Hour
)

func (s *Service) startWorker() {
	s.startOnce.Do(func() {
		go s.worker()
	})
}

func (s *Service) worker() {
	defer close(s.stopped)
	ticker := time.NewTicker(workerPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			s.runStaleInvalidations()
			s.runDueSync()
		case <-s.signal:
			s.runStaleInvalidations()
			s.runDueSync()
		}
	}
}

func (s *Service) runStaleInvalidations() {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		now := time.Now().UTC()
		integration, err := s.repository.claimStaleIntegration(
			ctx,
			now,
			now.Add(-s.cacheMaxAge),
		)
		cancel()
		if err != nil {
			log.WithError(err).Warn("failed to claim stale local EDR snapshot")
			return
		}
		if integration == nil {
			return
		}
		s.notifyPeers(context.Background(), integration.AccountID, integration.Groups)
	}
}

func (s *Service) runDueSync() {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), s.syncTimeout)
		integration, err := s.repository.claimDueIntegration(
			ctx,
			time.Now().UTC(),
			s.workerID,
			s.syncTimeout+30*time.Second,
		)
		if err != nil {
			cancel()
			log.WithError(err).Warn("failed to claim local EDR synchronization")
			return
		}
		if integration == nil {
			cancel()
			return
		}
		s.syncIntegration(ctx, integration)
		cancel()
	}
}

func (s *Service) syncIntegration(ctx context.Context, integration *edrmodel.Integration) {
	config, err := decryptProviderConfig(s.encryptor, integration.EncryptedConfig)
	if err == nil {
		filter, filterErr := s.deviceIdentityFilterForGroups(ctx, integration.AccountID, integration.Groups)
		err = filterErr
		if err == nil {
			var snapshots []deviceSnapshot
			snapshots, err = s.fetchDevices(ctx, integration.Provider, config, filter)
			if err == nil {
				now := time.Now().UTC()
				err = s.repository.replaceDevices(
					ctx,
					integration.ID,
					integration.AccountID,
					snapshotsToModels(snapshots),
					now,
					now.Add(s.syncInterval),
					s.workerID,
				)
				if err == nil {
					s.notifyPeers(ctx, integration.AccountID, integration.Groups)
					return
				}
			}
		}
	}
	delay := retryDelay(integration.FailureCount + 1)
	failureCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if markErr := s.repository.markSyncFailure(
		failureCtx,
		integration.ID,
		time.Now().UTC().Add(delay),
		fmt.Sprintf("%v", err),
		s.workerID,
	); markErr != nil {
		log.WithError(markErr).Warn("failed to record local EDR synchronization error")
	}
	log.WithError(err).
		WithField("provider", integration.Provider).
		WithField("account_id", integration.AccountID).
		Warnf("local EDR synchronization failed; retrying in %s", delay)
}

func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	exponent := min(attempt-1, 6)
	delay := time.Minute * time.Duration(math.Pow(2, float64(exponent)))
	if delay > maxRetryDelay {
		return maxRetryDelay
	}
	return delay
}

func (s *Service) stopWorker(ctx context.Context) {
	s.stopOnce.Do(func() {
		close(s.stop)
	})
	select {
	case <-s.stopped:
	case <-ctx.Done():
	}
}
