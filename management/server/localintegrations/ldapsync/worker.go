package ldapsync

import (
	"context"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/activity"
	ldapsyncmodel "github.com/netbirdio/netbird/management/server/localintegrations/ldapsync/model"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	workerPollInterval = 30 * time.Second
	runLeaseDuration   = 5 * time.Minute
	runLeaseRenewAfter = runLeaseDuration / 3
	maxFailureCount    = 5
)

// Start launches the durable database-backed worker once. It exits with the
// Management server context and never requires Redis or an external scheduler.
func (s *Service) Start(ctx context.Context) {
	s.startOnce.Do(func() {
		if err := s.requirePostgresAndKey(); err != nil {
			log.WithContext(ctx).WithError(err).Warn("local LDAP sync worker is disabled")
			return
		}
		go s.runWorker(ctx)
	})
}

func (s *Service) runWorker(ctx context.Context) {
	ticker := time.NewTicker(workerPollInterval)
	defer ticker.Stop()
	for {
		s.workerIteration(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) workerIteration(ctx context.Context) {
	if err := s.scheduleDueRuns(ctx, time.Now().UTC()); err != nil {
		log.WithContext(ctx).WithError(err).Error("failed to schedule local LDAP sync runs")
		s.metrics.recordWorkerFailure(ctx, "scheduler", "schedule_failed")
	}
	if depth, err := s.store.CountLDAPSyncRuns(ctx, ldapsyncmodel.RunStatusQueued); err != nil {
		log.WithContext(ctx).WithError(err).Warn("failed to count local LDAP sync queue depth")
	} else {
		s.metrics.setQueueDepth(depth)
	}
	for {
		run, err := s.store.ClaimLDAPSyncRun(ctx, time.Now().UTC(), runLeaseDuration, s.workerID)
		if err != nil {
			log.WithContext(ctx).WithError(err).Error("failed to claim local LDAP sync run")
			return
		}
		if run == nil {
			return
		}
		s.executeRun(ctx, run)
	}
}

func (s *Service) scheduleDueRuns(ctx context.Context, now time.Time) error {
	for _, account := range s.store.GetAllAccounts(ctx) {
		configs, err := s.store.ListLDAPSyncConfigs(ctx, account.Id)
		if err != nil {
			return err
		}
		for _, config := range configs {
			if !config.Enabled || config.PausedReason != "" || config.NextRunAt == nil || config.NextRunAt.After(now) {
				continue
			}
			if _, err := s.createRun(ctx, config, "", ldapsyncmodel.RunTriggerScheduled, "", ""); err != nil && !isStatusType(err, status.AlreadyExists) {
				return err
			}
			next := now.Add(time.Duration(config.IntervalMinutes) * time.Minute)
			config.NextRunAt = &next
			if err := s.store.UpdateLDAPSyncConfigRuntime(ctx, config); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) executeRun(ctx context.Context, run *ldapsyncmodel.Run) {
	lastLeaseRenewal := time.Now().UTC()
	config, err := s.store.GetLDAPSyncConfig(ctx, run.AccountID, run.ConnectorID)
	if err != nil {
		s.failRun(ctx, run, nil, "config_not_found", "synchronization configuration is unavailable", false)
		return
	}
	if run.ConfigRevision != config.Revision {
		s.failRun(ctx, run, nil, "config_revision_changed", "synchronization configuration changed after the run was queued", false)
		return
	}
	plan, err := s.buildPlan(ctx, config)
	if err != nil {
		retryable := strings.Contains(strings.ToLower(err.Error()), "connection failed")
		s.failRun(ctx, run, config, "ldap_source_unavailable", err.Error(), retryable)
		return
	}
	if !s.renewRunLease(ctx, run, &lastLeaseRenewal, true) {
		return
	}
	if plan.highRisk && (run.ConfirmationTokenHash == "" || run.SourceFingerprint != plan.sourceFingerprint) {
		run.Status = ldapsyncmodel.RunStatusAwaitingApproval
		run.SourceFingerprint = plan.sourceFingerprint
		run.ErrorCode = "high_risk_confirmation_required"
		run.ErrorSummary = plan.highRiskReason
		run.LeaseUntil = nil
		if owned, err := s.updateClaimedRun(ctx, run); err != nil {
			log.WithContext(ctx).WithError(err).WithField("run_id", run.ID).Error("failed to pause high-risk local LDAP sync run")
		} else if !owned {
			log.WithContext(ctx).WithField("run_id", run.ID).Warn("discarded high-risk transition after local LDAP sync lease was lost")
		}
		return
	}

	for index := range plan.actions {
		if !s.renewRunLease(ctx, run, &lastLeaseRenewal, false) {
			return
		}
		action := &plan.actions[index]
		switch action.kind {
		case "skipped":
			run.SkippedCount++
		case "unchanged":
			if err := s.applyAction(ctx, config, action); err != nil {
				run.ErrorCount++
				log.WithContext(ctx).WithError(err).WithFields(log.Fields{
					"run_id":         run.ID,
					"account_id":     run.AccountID,
					"connector_id":   run.ConnectorID,
					"source_id_hash": shortHash(action.externalIDHash),
				}).Error("failed to refresh unchanged local LDAP sync object")
				continue
			}
			run.SkippedCount++
		case "conflict":
			run.ConflictCount++
		case "create", "update", "disable":
			if err := s.applyAction(ctx, config, action); err != nil {
				run.ErrorCount++
				log.WithContext(ctx).WithError(err).WithFields(log.Fields{
					"run_id":         run.ID,
					"account_id":     run.AccountID,
					"connector_id":   run.ConnectorID,
					"source_id_hash": shortHash(action.externalIDHash),
				}).Error("failed to apply local LDAP sync object")
				continue
			}
			switch action.kind {
			case "create":
				run.CreatedCount++
			case "update":
				run.UpdatedCount++
			case "disable":
				run.DisabledCount++
			}
		}
	}

	finishedAt := time.Now().UTC()
	run.FinishedAt = &finishedAt
	run.LeaseUntil = nil
	if run.ErrorCount > 0 {
		run.Status = ldapsyncmodel.RunStatusPartial
		run.ErrorCode = "object_apply_failed"
		run.ErrorSummary = fmt.Sprintf("%d LDAP objects could not be applied", run.ErrorCount)
	} else {
		run.Status = ldapsyncmodel.RunStatusSuccess
		run.ErrorCode = ""
		run.ErrorSummary = ""
	}
	owned, err := s.updateClaimedRun(ctx, run)
	if err != nil {
		log.WithContext(ctx).WithError(err).WithField("run_id", run.ID).Error("failed to finalize local LDAP sync run")
		return
	}
	if !owned {
		log.WithContext(ctx).WithField("run_id", run.ID).Warn("discarded local LDAP sync result after lease was lost")
		return
	}
	s.metrics.recordRun(ctx, run)
	if run.Status == ldapsyncmodel.RunStatusSuccess {
		config.FailureCount = 0
		config.PausedReason = ""
		config.LastSuccessAt = &finishedAt
	} else {
		config.FailureCount++
		if config.FailureCount >= maxFailureCount {
			config.PausedReason = "consecutive_partial_runs"
			config.NextRunAt = nil
		}
	}
	if config.Enabled && config.PausedReason == "" {
		next := finishedAt.Add(time.Duration(config.IntervalMinutes) * time.Minute)
		config.NextRunAt = &next
	}
	if err := s.store.UpdateLDAPSyncConfigRuntime(ctx, config); err != nil {
		log.WithContext(ctx).WithError(err).WithField("run_id", run.ID).Error("failed to update local LDAP sync runtime status")
	}
}

func (s *Service) applyAction(ctx context.Context, config *ldapsyncmodel.Config, action *planAction) error {
	now := time.Now().UTC()
	object := action.object
	switch action.kind {
	case "create":
		name := strings.TrimSpace(action.source.Name)
		if name == "" {
			name = action.source.Email
		}
		user := types.NewUser(
			dex.EncodeDexUserID(action.source.StableID, config.ConnectorID),
			types.UserRoleUser,
			false,
			false,
			"",
			action.desiredAutoGroups,
			types.UserIssuedIntegration,
			action.source.Email,
			name,
		)
		user.AccountID = config.AccountID
		user.MFAPolicy = types.MFAPolicyInherit
		user.IntegrationReference = integrationReferenceForConfig(config)
		if _, err := s.events.SaveOrAddUser(ctx, config.AccountID, activity.SystemInitiator, user, true); err != nil {
			return err
		}
		object.NetBirdObjectID = user.Id
	case "update":
		user := action.user.Copy()
		user.Name = action.source.Name
		user.Email = action.source.Email
		user.AutoGroups = action.desiredAutoGroups
		if user.LDAPSyncBlocked {
			user.Blocked = false
			user.LDAPSyncBlocked = false
		}
		user.IntegrationReference = integrationReferenceForConfig(config)
		if _, err := s.events.SaveUser(ctx, config.AccountID, activity.SystemInitiator, user); err != nil {
			return err
		}
		object.NetBirdObjectID = user.Id
	case "disable":
		user := action.user.Copy()
		if !user.Blocked {
			user.Blocked = true
			user.LDAPSyncBlocked = true
		}
		if _, err := s.events.SaveUser(ctx, config.AccountID, activity.SystemInitiator, user); err != nil {
			return err
		}
		object.Status = ldapsyncmodel.ObjectStatusDisabled
	case "unchanged":
		// An unchanged source can still be the first observation of a user
		// that already exists through the same LDAP Connector. Persist the
		// association so the next run does not treat it as a missing user.
		object.NetBirdObjectID = action.user.Id
	}

	if action.kind != "disable" {
		object.Status = ldapsyncmodel.ObjectStatusActive
		object.SourceFingerprint = sourceUserFingerprint(action.source, action.desiredAutoGroups)
		object.ManagedFields = action.managedFields
	}
	object.LastSeenAt = now
	return s.store.SaveLDAPSyncObjects(ctx, []*ldapsyncmodel.Object{object})
}

func (s *Service) failRun(ctx context.Context, run *ldapsyncmodel.Run, config *ldapsyncmodel.Config, code, summary string, retryable bool) {
	now := time.Now().UTC()
	run.Status = ldapsyncmodel.RunStatusFailed
	run.ErrorCode = code
	run.ErrorSummary = truncateErrorSummary(summary)
	run.ErrorCount++
	run.FinishedAt = &now
	run.LeaseUntil = nil
	owned, err := s.updateClaimedRun(ctx, run)
	if err != nil {
		log.WithContext(ctx).WithError(err).WithField("run_id", run.ID).Error("failed to record local LDAP sync failure")
	}
	if !owned {
		log.WithContext(ctx).WithField("run_id", run.ID).Warn("discarded local LDAP sync failure after lease was lost")
		return
	}
	s.metrics.recordRun(ctx, run)
	if config == nil {
		return
	}
	config.FailureCount++
	if !retryable {
		config.PausedReason = "configuration_error"
		config.NextRunAt = nil
	} else if config.FailureCount >= maxFailureCount {
		config.PausedReason = "consecutive_failures"
		config.NextRunAt = nil
	} else if config.Enabled {
		backoff := time.Duration(1<<min(config.FailureCount-1, 5)) * 5 * time.Minute
		next := now.Add(backoff)
		config.NextRunAt = &next
	}
	if err := s.store.UpdateLDAPSyncConfigRuntime(ctx, config); err != nil {
		log.WithContext(ctx).WithError(err).WithField("run_id", run.ID).Error("failed to record local LDAP sync failure state")
	}
}

func (s *Service) renewRunLease(ctx context.Context, run *ldapsyncmodel.Run, lastRenewal *time.Time, force bool) bool {
	if run.LeaseOwner == "" {
		return true
	}
	now := time.Now().UTC()
	if !force && now.Sub(*lastRenewal) < runLeaseRenewAfter {
		return true
	}
	owned, err := s.store.RenewLDAPSyncRunLease(ctx, run.AccountID, run.ConnectorID, run.ID, run.LeaseOwner, now, runLeaseDuration)
	if err != nil {
		log.WithContext(ctx).WithError(err).WithField("run_id", run.ID).Error("failed to renew local LDAP sync run lease")
		return false
	}
	if !owned {
		log.WithContext(ctx).WithField("run_id", run.ID).Warn("local LDAP sync run lease was reclaimed by another worker")
		return false
	}
	leaseUntil := now.Add(runLeaseDuration)
	run.LeaseUntil = &leaseUntil
	*lastRenewal = now
	return true
}

func (s *Service) updateClaimedRun(ctx context.Context, run *ldapsyncmodel.Run) (bool, error) {
	leaseOwner := run.LeaseOwner
	if leaseOwner == "" {
		return true, s.store.UpdateLDAPSyncRun(ctx, run)
	}
	run.LeaseOwner = ""
	owned, err := s.store.UpdateLDAPSyncRunOwned(ctx, run, leaseOwner)
	if err != nil || !owned {
		run.LeaseOwner = leaseOwner
	}
	return owned, err
}

func truncateErrorSummary(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 512 {
		return value
	}
	return value[:512]
}
