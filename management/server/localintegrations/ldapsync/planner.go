package ldapsync

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"time"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/integration_reference"
	ldapsyncmodel "github.com/netbirdio/netbird/management/server/localintegrations/ldapsync/model"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	previewSampleLimit = 20
	previewUserLimit   = 5000
	previewGroupLimit  = 1000
)

type planAction struct {
	kind              string
	externalIDHash    string
	source            *dex.LDAPDirectoryUser
	user              *types.User
	object            *ldapsyncmodel.Object
	desiredAutoGroups []string
	managedFields     []string
	reason            string
}

type syncPlan struct {
	actions           []planAction
	counts            PreviewCounts
	sourceFingerprint string
	highRisk          bool
	highRiskReason    string
}

func (s *Service) Preview(ctx context.Context, accountID, connectorID, userID string) (*PreviewResponse, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}
	if err := s.requirePostgresAndKey(); err != nil {
		return nil, err
	}
	config, err := s.store.GetLDAPSyncConfig(ctx, accountID, connectorID)
	if err != nil {
		return nil, err
	}
	plan, err := s.buildPlan(ctx, config)
	if err != nil {
		return nil, err
	}

	response := previewResponse(plan)
	if plan.highRisk {
		token, expiresAt, err := s.issueConfirmationToken(config, plan.sourceFingerprint)
		if err != nil {
			return nil, err
		}
		response.ConfirmationToken = token
		response.ConfirmationExpires = &expiresAt
	}
	s.events.StoreEvent(ctx, userID, connectorID, accountID, activity.LocalLDAPSyncPreviewed, map[string]any{
		"created":   plan.counts.Created,
		"updated":   plan.counts.Updated,
		"disabled":  plan.counts.Disabled,
		"conflicts": plan.counts.Conflicts,
		"high_risk": plan.highRisk,
	})
	return response, nil
}

func (s *Service) QueueRun(ctx context.Context, accountID, connectorID, userID, confirmationToken string) (*ldapsyncmodel.Run, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}
	if err := s.requirePostgresAndKey(); err != nil {
		return nil, err
	}
	config, err := s.store.GetLDAPSyncConfig(ctx, accountID, connectorID)
	if err != nil {
		return nil, err
	}
	if !config.Enabled {
		return nil, status.Errorf(status.PreconditionFailed, "local LDAP synchronization is not enabled")
	}
	plan, err := s.buildPlan(ctx, config)
	if err != nil {
		return nil, err
	}
	tokenHash := ""
	if plan.highRisk {
		if err := s.validateConfirmationToken(confirmationToken, config, plan.sourceFingerprint); err != nil {
			return nil, err
		}
		tokenHash = fullHash(confirmationToken)
	}
	run, err := s.createRun(ctx, config, userID, ldapsyncmodel.RunTriggerManual, plan.sourceFingerprint, tokenHash)
	if err != nil {
		return nil, err
	}
	s.events.StoreEvent(ctx, userID, connectorID, accountID, activity.LocalLDAPSyncRunCreated, map[string]any{"run_id": run.ID})
	return run, nil
}

func (s *Service) ConfirmRun(ctx context.Context, accountID, connectorID, runID, userID, confirmationToken string) (*ldapsyncmodel.Run, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return nil, err
	}
	run, err := s.store.GetLDAPSyncRun(ctx, accountID, connectorID, runID)
	if err != nil {
		return nil, err
	}
	if run.Status != ldapsyncmodel.RunStatusAwaitingApproval {
		return nil, status.Errorf(status.PreconditionFailed, "sync run is not awaiting approval")
	}
	config, err := s.store.GetLDAPSyncConfig(ctx, accountID, connectorID)
	if err != nil {
		return nil, err
	}
	plan, err := s.buildPlan(ctx, config)
	if err != nil {
		return nil, err
	}
	if !plan.highRisk {
		return nil, status.Errorf(status.PreconditionFailed, "sync run no longer requires high-risk approval")
	}
	if err := s.validateConfirmationToken(confirmationToken, config, plan.sourceFingerprint); err != nil {
		return nil, err
	}
	run.Status = ldapsyncmodel.RunStatusQueued
	run.SourceFingerprint = plan.sourceFingerprint
	run.ConfirmationTokenHash = fullHash(confirmationToken)
	run.StartedAt = nil
	run.FinishedAt = nil
	run.LeaseUntil = nil
	run.ErrorCode = ""
	run.ErrorSummary = ""
	if err := s.store.UpdateLDAPSyncRun(ctx, run); err != nil {
		return nil, err
	}
	s.events.StoreEvent(ctx, userID, connectorID, accountID, activity.LocalLDAPSyncRunConfirmed, map[string]any{"run_id": run.ID})
	return run, nil
}

func (s *Service) buildPlan(ctx context.Context, config *ldapsyncmodel.Config) (*syncPlan, error) {
	connector, err := s.ldapConnector(ctx, config.AccountID, config.ConnectorID)
	if err != nil {
		return nil, err
	}
	snapshot, err := dex.ReadLDAPDirectory(connector.LDAP, config.SyncScopeGroups, previewUserLimit, previewGroupLimit)
	if err != nil {
		return nil, status.Errorf(status.PreconditionFailed, "failed to read LDAP synchronization source: %v", sanitizeSyncError(err))
	}
	objects, err := s.store.GetLDAPSyncObjects(ctx, config.AccountID, config.ConnectorID, ldapsyncmodel.ObjectTypeUser)
	if err != nil {
		return nil, err
	}
	users, err := s.store.GetAccountUsers(ctx, store.LockingStrengthNone, config.AccountID)
	if err != nil {
		return nil, err
	}

	objectByExternalID := make(map[string]*ldapsyncmodel.Object, len(objects))
	activeManaged := 0
	for _, object := range objects {
		objectByExternalID[object.ExternalID] = object
		if object.Status == ldapsyncmodel.ObjectStatusActive {
			activeManaged++
		}
	}
	userByID := make(map[string]*types.User, len(users))
	userByEmail := make(map[string]*types.User, len(users))
	userByConnectorStableID := make(map[string]*types.User)
	for _, user := range users {
		userByID[user.Id] = user
		if user.Email != "" {
			userByEmail[strings.ToLower(user.Email)] = user
		}
		stableID, connectorID, decodeErr := dex.DecodeDexUserID(user.Id)
		if decodeErr == nil && connectorID == config.ConnectorID {
			userByConnectorStableID[stableID] = user
		}
	}

	mappedGroups := make(map[string][]string, len(config.GroupMappings))
	for _, mapping := range config.GroupMappings {
		mappedGroups[strings.ToLower(mapping.LDAPGroup)] = mapping.NetBirdAutoGroupIDs
	}
	slices.SortFunc(snapshot.Users, func(a, b dex.LDAPDirectoryUser) int {
		return strings.Compare(a.StableID, b.StableID)
	})

	plan := &syncPlan{actions: make([]planAction, 0, len(snapshot.Users)+len(objects))}
	seenExternalIDs := make(map[string]struct{}, len(snapshot.Users))
	seenStableIDs := make(map[string]struct{}, len(snapshot.Users))
	for index := range snapshot.Users {
		source := &snapshot.Users[index]
		externalIDHash := s.externalIDHash(config.AccountID, config.ConnectorID, source.StableID)
		if strings.TrimSpace(source.StableID) == "" {
			plan.addAction(planAction{kind: "skipped", externalIDHash: externalIDHash, source: source, reason: "missing or invalid stable ID/email"})
			continue
		}
		if _, duplicate := seenStableIDs[source.StableID]; duplicate {
			plan.addAction(planAction{kind: "conflict", externalIDHash: externalIDHash, source: source, reason: "duplicate LDAP stable ID"})
			continue
		}
		seenStableIDs[source.StableID] = struct{}{}
		seenExternalIDs[externalIDHash] = struct{}{}
		if !validEmail(source.Email) {
			plan.addAction(planAction{kind: "skipped", externalIDHash: externalIDHash, source: source, reason: "missing or invalid stable ID/email"})
			continue
		}

		object := objectByExternalID[externalIDHash]
		var user *types.User
		if object != nil {
			user = userByID[object.NetBirdObjectID]
			// Recover mappings created by an interrupted or older synchronization
			// that did not persist the NetBird user ID. The connector-scoped Dex
			// identity is deterministic, so it is safe to repair this association.
			if user == nil {
				user = userByConnectorStableID[source.StableID]
				if user == nil {
					user = userByID[dex.EncodeDexUserID(source.StableID, config.ConnectorID)]
				}
			}
			if user == nil {
				plan.addAction(planAction{kind: "conflict", externalIDHash: externalIDHash, source: source, object: object, reason: "managed NetBird user no longer exists"})
				continue
			}
		} else {
			user = userByConnectorStableID[source.StableID]
			if user == nil {
				user = userByID[dex.EncodeDexUserID(source.StableID, config.ConnectorID)]
			}
		}

		if conflicting := userByEmail[strings.ToLower(source.Email)]; conflicting != nil && (user == nil || conflicting.Id != user.Id) {
			plan.addAction(planAction{kind: "conflict", externalIDHash: externalIDHash, source: source, object: object, reason: "email belongs to an unmanaged NetBird user"})
			continue
		}
		desiredGroups := desiredAutoGroups(source.Groups, mappedGroups)
		managedFields := managedFieldsForGroups(desiredGroups)
		fingerprint := sourceUserFingerprint(source, desiredGroups)
		if object == nil {
			object = &ldapsyncmodel.Object{
				AccountID:         config.AccountID,
				ConnectorID:       config.ConnectorID,
				ObjectType:        ldapsyncmodel.ObjectTypeUser,
				ExternalID:        externalIDHash,
				SourceFingerprint: fingerprint,
				ManagedFields:     managedFields,
				Status:            ldapsyncmodel.ObjectStatusActive,
			}
		}
		if user == nil {
			plan.addAction(planAction{kind: "create", externalIDHash: externalIDHash, source: source, object: object, desiredAutoGroups: desiredGroups, managedFields: managedFields})
			continue
		}
		if user.DirectoryDeletionPending {
			plan.addAction(planAction{kind: "conflict", externalIDHash: externalIDHash, source: source, user: user, object: object, reason: "user directory deletion is pending"})
			continue
		}
		if user.Role != types.UserRoleUser {
			plan.addAction(planAction{kind: "conflict", externalIDHash: externalIDHash, source: source, user: user, object: object, reason: "synchronization cannot manage a privileged user"})
			continue
		}
		desiredEffectiveGroups := mergeManagedAutoGroups(user.AutoGroups, object.ManagedFields, desiredGroups)
		needsUpdate := user.Name != source.Name || !strings.EqualFold(user.Email, source.Email) || user.LDAPSyncBlocked || !slices.Equal(normalizeStrings(user.AutoGroups), normalizeStrings(desiredEffectiveGroups)) || object.SourceFingerprint != fingerprint
		kind := "unchanged"
		if needsUpdate {
			kind = "update"
		}
		plan.addAction(planAction{kind: kind, externalIDHash: externalIDHash, source: source, user: user, object: object, desiredAutoGroups: desiredEffectiveGroups, managedFields: managedFields})
	}

	if config.DeprovisionAction == ldapsyncmodel.DeprovisionDisable {
		for _, object := range objects {
			if _, seen := seenExternalIDs[object.ExternalID]; seen || object.Status == ldapsyncmodel.ObjectStatusDisabled {
				continue
			}
			user := userByID[object.NetBirdObjectID]
			if user == nil || user.Blocked {
				continue
			}
			plan.addAction(planAction{kind: "disable", externalIDHash: object.ExternalID, user: user, object: object, reason: "LDAP object left synchronization scope"})
		}
	}

	plan.sourceFingerprint = planFingerprint(config.Revision, plan.actions)
	plan.highRisk, plan.highRiskReason = disableRisk(plan.counts.Disabled, activeManaged)
	return plan, nil
}

func disableRisk(disabled, activeManaged int) (bool, string) {
	if disabled <= 100 && (activeManaged == 0 || disabled*100 <= activeManaged*20) {
		return false, ""
	}
	return true, fmt.Sprintf("would disable %d of %d active managed users", disabled, activeManaged)
}

func (p *syncPlan) addAction(action planAction) {
	p.actions = append(p.actions, action)
	switch action.kind {
	case "create":
		p.counts.Created++
	case "update":
		p.counts.Updated++
	case "disable":
		p.counts.Disabled++
	case "unchanged":
		p.counts.Unchanged++
	case "skipped":
		p.counts.Skipped++
	case "conflict":
		p.counts.Conflicts++
	}
}

func previewResponse(plan *syncPlan) *PreviewResponse {
	response := &PreviewResponse{
		Counts:            plan.counts,
		SourceFingerprint: plan.sourceFingerprint,
		HighRisk:          plan.highRisk,
		HighRiskReason:    plan.highRiskReason,
	}
	for _, action := range plan.actions {
		if len(response.Samples) >= previewSampleLimit || action.kind == "unchanged" {
			continue
		}
		sample := PreviewSample{Action: action.kind, ExternalIDHash: shortHash(action.externalIDHash), Reason: action.reason}
		if action.source != nil {
			sample.Email = action.source.Email
			sample.Name = action.source.Name
		} else if action.user != nil {
			sample.Email = action.user.Email
			sample.Name = action.user.Name
		}
		response.Samples = append(response.Samples, sample)
	}
	return response
}

func (s *Service) externalIDHash(accountID, connectorID, stableID string) string {
	mac := hmac.New(sha256.New, s.syncKey)
	_, _ = mac.Write([]byte(accountID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(connectorID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(stableID))
	return fmt.Sprintf("%x", mac.Sum(nil))
}

func sourceUserFingerprint(user *dex.LDAPDirectoryUser, autoGroups []string) string {
	groups := append([]string(nil), user.Groups...)
	slices.Sort(groups)
	autoGroups = append([]string(nil), autoGroups...)
	slices.Sort(autoGroups)
	return fullHash(strings.Join([]string{user.StableID, strings.ToLower(user.Email), user.Name, strings.Join(groups, "\x1f"), strings.Join(autoGroups, "\x1f")}, "\x00"))
}

func planFingerprint(revision int64, actions []planAction) string {
	parts := make([]string, 0, len(actions)+1)
	parts = append(parts, fmt.Sprintf("revision:%d", revision))
	for _, action := range actions {
		fingerprint := action.kind + ":" + action.externalIDHash
		if action.source != nil {
			fingerprint += ":" + sourceUserFingerprint(action.source, action.desiredAutoGroups)
		}
		parts = append(parts, fingerprint)
	}
	slices.Sort(parts[1:])
	return fullHash(strings.Join(parts, "\n"))
}

func desiredAutoGroups(ldapGroups []string, mappings map[string][]string) []string {
	result := make([]string, 0)
	for _, ldapGroup := range ldapGroups {
		result = append(result, mappings[strings.ToLower(ldapGroup)]...)
	}
	return normalizeStrings(result)
}

func managedFieldsForGroups(groupIDs []string) []string {
	fields := []string{"name", "email", "blocked"}
	for _, groupID := range groupIDs {
		fields = append(fields, "auto_group:"+groupID)
	}
	return fields
}

func mergeManagedAutoGroups(current, previousManagedFields, desired []string) []string {
	previousManaged := make(map[string]struct{})
	for _, field := range previousManagedFields {
		if value, ok := strings.CutPrefix(field, "auto_group:"); ok {
			previousManaged[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(current)+len(desired))
	for _, groupID := range current {
		if _, managed := previousManaged[groupID]; !managed {
			result = append(result, groupID)
		}
	}
	result = append(result, desired...)
	return normalizeStrings(result)
}

func validEmail(value string) bool {
	parsed, err := mail.ParseAddress(value)
	return err == nil && strings.EqualFold(parsed.Address, value) && strings.Contains(value, "@")
}

func sanitizeSyncError(err error) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "bind"):
		return "LDAP bind failed"
	case strings.Contains(message, "connect"), strings.Contains(message, "dial"), strings.Contains(message, "timeout"):
		return "LDAP connection failed"
	case strings.Contains(message, "limit exceeded"):
		return "LDAP directory result limit exceeded"
	case strings.Contains(message, "filter"):
		return "LDAP search filter is invalid"
	default:
		return "LDAP directory read failed"
	}
}

func fullHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:])
}

func integrationReferenceForConfig(config *ldapsyncmodel.Config) integration_reference.IntegrationReference {
	return integration_reference.IntegrationReference{ID: int(config.ID), IntegrationType: "local_ldap_sync"}
}

func nowUTC() time.Time { return time.Now().UTC() }
