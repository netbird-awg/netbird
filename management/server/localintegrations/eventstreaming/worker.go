package eventstreaming

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"

	eventmodel "github.com/netbirdio/netbird/management/server/localintegrations/eventstreaming/model"
)

const (
	workerPollInterval  = 5 * time.Second
	deliveryTimeout     = 45 * time.Second
	deliveryLease       = 2 * time.Minute
	maxDeliveryAttempts = 8
	maxDeliveryBackoff  = 15 * time.Minute
)

func (s *Service) Start(ctx context.Context) {
	s.startOnce.Do(func() {
		go s.runWorker(ctx)
	})
}

func (s *Service) runWorker(ctx context.Context) {
	poll := time.NewTicker(workerPollInterval)
	prune := time.NewTicker(6 * time.Hour)
	defer poll.Stop()
	defer prune.Stop()
	for {
		if err := s.drainOutbox(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.WithContext(ctx).WithError(err).Error("event streaming worker iteration failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-poll.C:
		case <-s.signal:
		case now := <-prune.C:
			if err := s.repository.prune(ctx, now.UTC()); err != nil {
				log.WithContext(ctx).WithError(err).Warn("failed to prune event streaming outbox")
			}
		}
	}
}

func (s *Service) drainOutbox(ctx context.Context) error {
	for {
		item, err := s.repository.claim(ctx, time.Now().UTC(), deliveryLease, s.workerID)
		if err != nil {
			return err
		}
		if item == nil {
			return nil
		}
		s.executeDelivery(ctx, item)
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

func (s *Service) executeDelivery(ctx context.Context, item *eventmodel.Outbox) {
	integration, err := s.repository.integrationByID(ctx, item.IntegrationID)
	if err == nil && (integration == nil || !integration.Enabled) {
		err = permanentDeliveryError("event streaming integration is unavailable or disabled")
	}

	var rawPayload []byte
	var event StreamEvent
	var config map[string]string
	if err == nil {
		plain, decryptErr := s.encryptor.Decrypt(item.EncryptedPayload)
		if decryptErr != nil {
			err = permanentDeliveryError("queued event payload cannot be decrypted")
		} else {
			rawPayload = []byte(plain)
			if jsonErr := json.Unmarshal(rawPayload, &event); jsonErr != nil {
				err = permanentDeliveryError("queued event payload is invalid")
			}
		}
	}
	if err == nil {
		config, err = s.decryptConfig(integration.EncryptedConfig)
	}
	if err == nil {
		deliveryCtx, cancel := context.WithTimeout(ctx, deliveryTimeout)
		err = s.deliver(deliveryCtx, integration, config, event, rawPayload)
		cancel()
	}

	nextAttempt := time.Now().UTC().Add(deliveryBackoff(item.Attempts + 1))
	finishCtx, cancelFinish := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancelFinish()
	if finishErr := s.repository.finish(
		finishCtx,
		item,
		s.workerID,
		err,
		maxDeliveryAttempts,
		nextAttempt,
	); finishErr != nil {
		log.WithContext(ctx).WithError(finishErr).
			WithField("outbox_id", item.ID).
			Error("failed to finalize event streaming delivery")
		return
	}
	if err != nil {
		log.WithContext(ctx).
			WithField("outbox_id", item.ID).
			WithField("attempt", item.Attempts+1).
			Warn(sanitizeDeliveryError(err))
	}
}

func deliveryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	backoff := time.Second << min(attempt-1, 10)
	if backoff > maxDeliveryBackoff {
		return maxDeliveryBackoff
	}
	return backoff
}
