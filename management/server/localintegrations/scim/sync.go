package scim

import (
	"context"
	"fmt"
	"slices"
	"strings"

	scimlib "github.com/elimity-com/scim"
	"github.com/rs/xid"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/integration_reference"
	"github.com/netbirdio/netbird/management/server/localintegrations/idconv"
	scimmodel "github.com/netbirdio/netbird/management/server/localintegrations/scim/model"
	"github.com/netbirdio/netbird/management/server/types"
)

const maxStagedResourcesPerType = 100000

type syncSummary struct {
	Users    int
	Groups   int
	Skipped  int
	Disabled int
}

type sourceGroup struct {
	resource *scimmodel.Resource
	name     string
	members  []string
}

type sourceUser struct {
	resource *scimmodel.Resource
	stableID string
	email    string
	name     string
	active   bool
}

func (s *Service) syncIntegration(ctx context.Context, integration *scimmodel.Integration) (syncSummary, error) {
	var summary syncSummary
	groupResources, err := s.store.ListSCIMResources(
		ctx, integration.ID, scimmodel.ResourceTypeGroup, true,
	)
	if err != nil {
		return summary, fmt.Errorf("list staged groups: %w", err)
	}
	userResources, err := s.store.ListSCIMResources(
		ctx, integration.ID, scimmodel.ResourceTypeUser, true,
	)
	if err != nil {
		return summary, fmt.Errorf("list staged users: %w", err)
	}
	if len(groupResources) > maxStagedResourcesPerType || len(userResources) > maxStagedResourcesPerType {
		return summary, fmt.Errorf("staged SCIM resource limit exceeded")
	}

	sourceGroups, err := s.readSourceGroups(groupResources)
	if err != nil {
		return summary, err
	}
	sourceUsers, err := s.readSourceUsers(userResources)
	if err != nil {
		return summary, err
	}

	groupTargets, skippedGroups, err := s.reconcileGroups(ctx, integration, sourceGroups)
	if err != nil {
		return summary, err
	}
	summary.Groups = len(groupTargets)
	summary.Skipped += skippedGroups

	userMemberships := buildUserMemberships(sourceGroups, groupTargets)
	eligibleUsers := buildEligibleUsers(sourceGroups, integration.UserGroupPrefixes)
	users, disabled, skippedUsers, err := s.reconcileUsers(
		ctx, integration, sourceUsers, userMemberships, eligibleUsers,
	)
	if err != nil {
		return summary, err
	}
	summary.Users = users
	summary.Disabled = disabled
	summary.Skipped += skippedUsers
	return summary, nil
}

func (s *Service) readSourceGroups(resources []*scimmodel.Resource) (map[string]*sourceGroup, error) {
	result := make(map[string]*sourceGroup, len(resources))
	for _, resource := range resources {
		attributes, err := s.decryptResource(resource)
		if err != nil {
			return nil, fmt.Errorf("decode staged group %s: %w", resource.ID, err)
		}
		result[resource.ID] = &sourceGroup{
			resource: resource,
			name:     attributeString(attributes, "displayName"),
			members:  memberIDs(attributes["members"]),
		}
	}
	return result, nil
}

func (s *Service) readSourceUsers(resources []*scimmodel.Resource) (map[string]*sourceUser, error) {
	result := make(map[string]*sourceUser, len(resources))
	for _, resource := range resources {
		attributes, err := s.decryptResource(resource)
		if err != nil {
			return nil, fmt.Errorf("decode staged user %s: %w", resource.ID, err)
		}
		stableID := attributeString(attributes, "externalId")
		if stableID == "" {
			stableID = resource.ID
		}
		result[resource.ID] = &sourceUser{
			resource: resource,
			stableID: stableID,
			email:    userEmail(attributes),
			name:     userDisplayName(attributes),
			active:   attributeBool(attributes, "active", true),
		}
	}
	return result, nil
}

func (s *Service) reconcileGroups(
	ctx context.Context,
	integration *scimmodel.Integration,
	sourceGroups map[string]*sourceGroup,
) (map[string]string, int, error) {
	existing, err := s.accounts.GetAllGroups(ctx, integration.AccountID, activity.SystemInitiator)
	if err != nil {
		return nil, 0, fmt.Errorf("list NetBird groups: %w", err)
	}
	byID := make(map[string]*types.Group, len(existing))
	byName := make(map[string]*types.Group, len(existing))
	for _, group := range existing {
		byID[group.ID] = group
		byName[strings.ToLower(group.Name)] = group
	}

	reference, err := integrationReference(integration)
	if err != nil {
		return nil, 0, err
	}
	targets := make(map[string]string)
	skipped := 0
	for sourceID, source := range sourceGroups {
		if source.resource.Deleted || source.name == "" || len(source.name) > 255 ||
			!matchesPrefixes(source.name, integration.GroupPrefixes) {
			continue
		}
		if source.resource.NetBirdObjectID != "" {
			if target := byID[source.resource.NetBirdObjectID]; ownedByIntegration(target.IntegrationReference, reference) {
				if target.Name != source.name {
					newNameKey := strings.ToLower(source.name)
					if conflict := byName[newNameKey]; conflict != nil && conflict.ID != target.ID {
						skipped++
						_ = s.addLog(ctx, integration.ID, "warn", "skipped group rename with a conflicting NetBird name")
						continue
					}
					update := target.Copy()
					update.Name = source.name
					if err := s.accounts.UpdateGroup(ctx, integration.AccountID, activity.SystemInitiator, update); err != nil {
						return nil, skipped, fmt.Errorf("update NetBird group: %w", err)
					}
					delete(byName, strings.ToLower(target.Name))
					byName[newNameKey] = update
					byID[update.ID] = update
				}
				targets[sourceID] = target.ID
				continue
			}
		}
		if conflict := byName[strings.ToLower(source.name)]; conflict != nil {
			skipped++
			_ = s.addLog(ctx, integration.ID, "warn", "skipped group with a conflicting NetBird name")
			continue
		}
		target := &types.Group{
			ID:                   xid.New().String(),
			Name:                 source.name,
			Issued:               types.GroupIssuedIntegration,
			IntegrationReference: reference,
		}
		if err := s.accounts.CreateGroup(ctx, integration.AccountID, activity.SystemInitiator, target); err != nil {
			return nil, skipped, fmt.Errorf("create NetBird group: %w", err)
		}
		if err := s.store.UpdateSCIMResourceTarget(
			ctx, integration.ID, scimmodel.ResourceTypeGroup, source.resource.ID, target.ID,
		); err != nil {
			return nil, skipped, fmt.Errorf("record NetBird group mapping: %w", err)
		}
		byID[target.ID] = target
		byName[strings.ToLower(target.Name)] = target
		targets[sourceID] = target.ID
	}
	return targets, skipped, nil
}

func (s *Service) reconcileUsers(
	ctx context.Context,
	integration *scimmodel.Integration,
	sourceUsers map[string]*sourceUser,
	memberships map[string][]string,
	eligibleUsers map[string]struct{},
) (synced, disabled, skipped int, err error) {
	existing, err := s.accounts.ListUsers(ctx, integration.AccountID)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("list NetBird users: %w", err)
	}
	byID := make(map[string]*types.User, len(existing))
	byEmail := make(map[string]*types.User, len(existing))
	for _, user := range existing {
		byID[user.Id] = user
		if user.Email != "" {
			byEmail[strings.ToLower(user.Email)] = user
		}
	}

	reference, err := integrationReference(integration)
	if err != nil {
		return 0, 0, 0, err
	}
	for sourceID, source := range sourceUsers {
		targetID := source.resource.NetBirdObjectID
		if targetID == "" {
			targetID = integrationUserID(integration, source.stableID)
		}
		target := byID[targetID]
		shouldSync := !source.resource.Deleted && source.active &&
			(len(integration.UserGroupPrefixes) == 0 || containsUser(eligibleUsers, sourceID))

		if !shouldSync {
			if target != nil && ownedByIntegration(target.IntegrationReference, reference) && !target.Blocked {
				update := target.Copy()
				update.Blocked = true
				if _, err := s.accounts.SaveUser(ctx, integration.AccountID, activity.SystemInitiator, update); err != nil {
					return synced, disabled, skipped, fmt.Errorf("disable NetBird user: %w", err)
				}
				disabled++
			}
			continue
		}
		if source.email == "" || len(source.email) > 320 ||
			source.stableID == "" || len(source.stableID) > 255 ||
			len(source.name) > 255 {
			skipped++
			_ = s.addLog(ctx, integration.ID, "warn", "skipped SCIM user with an invalid identifier, email, or name")
			continue
		}
		emailKey := strings.ToLower(source.email)
		if conflict := byEmail[emailKey]; conflict != nil && conflict.Id != targetID {
			skipped++
			_ = s.addLog(ctx, integration.ID, "warn", "skipped SCIM user with a conflicting NetBird email")
			continue
		}
		if target != nil && !ownedByIntegration(target.IntegrationReference, reference) {
			skipped++
			_ = s.addLog(ctx, integration.ID, "warn", "skipped SCIM user owned by another source")
			continue
		}

		autoGroups := append([]string(nil), memberships[sourceID]...)
		slices.Sort(autoGroups)
		var update *types.User
		if target == nil {
			update = types.NewUser(
				targetID,
				types.UserRoleUser,
				false,
				false,
				"",
				autoGroups,
				types.UserIssuedIntegration,
				source.email,
				source.name,
			)
			update.AccountID = integration.AccountID
			update.MFAPolicy = types.MFAPolicyInherit
			update.IntegrationReference = reference
		} else {
			update = target.Copy()
			update.Name = source.name
			update.Email = source.email
			update.AutoGroups = autoGroups
			update.Blocked = false
			update.Issued = types.UserIssuedIntegration
			update.IntegrationReference = reference
		}
		previousEmailKey := ""
		if target != nil {
			previousEmailKey = strings.ToLower(target.Email)
		}
		if _, err := s.accounts.SaveOrAddUser(
			ctx, integration.AccountID, activity.SystemInitiator, update, true,
		); err != nil {
			return synced, disabled, skipped, fmt.Errorf("save NetBird user: %w", err)
		}
		if source.resource.NetBirdObjectID != targetID {
			if err := s.store.UpdateSCIMResourceTarget(
				ctx, integration.ID, scimmodel.ResourceTypeUser, source.resource.ID, targetID,
			); err != nil {
				return synced, disabled, skipped, fmt.Errorf("record NetBird user mapping: %w", err)
			}
		}
		if previousEmailKey != "" && previousEmailKey != emailKey {
			if previous := byEmail[previousEmailKey]; previous != nil && previous.Id == targetID {
				delete(byEmail, previousEmailKey)
			}
		}
		byID[targetID] = update
		byEmail[emailKey] = update
		synced++
	}
	return synced, disabled, skipped, nil
}

func integrationReference(integration *scimmodel.Integration) (integration_reference.IntegrationReference, error) {
	id, err := idconv.Int(integration.ID)
	if err != nil {
		return integration_reference.IntegrationReference{}, fmt.Errorf("SCIM integration ID is out of range: %w", err)
	}
	return integration_reference.IntegrationReference{
		ID:              id,
		IntegrationType: scimmodel.IntegrationType,
	}, nil
}

func ownedByIntegration(actual, expected integration_reference.IntegrationReference) bool {
	return actual.ID == expected.ID && actual.IntegrationType == expected.IntegrationType
}

func integrationUserID(integration *scimmodel.Integration, stableID string) string {
	if integration.ConnectorID != "" {
		return dex.EncodeDexUserID(stableID, integration.ConnectorID)
	}
	if integration.Prefix != "" {
		return strings.TrimSuffix(integration.Prefix, "|") + "|" + stableID
	}
	return stableID
}

func buildUserMemberships(
	groups map[string]*sourceGroup,
	groupTargets map[string]string,
) map[string][]string {
	result := make(map[string][]string)
	for sourceGroupID, targetGroupID := range groupTargets {
		group := groups[sourceGroupID]
		if group == nil || group.resource.Deleted {
			continue
		}
		for _, memberID := range group.members {
			if !slices.Contains(result[memberID], targetGroupID) {
				result[memberID] = append(result[memberID], targetGroupID)
			}
		}
	}
	return result
}

func buildEligibleUsers(
	groups map[string]*sourceGroup,
	prefixes []string,
) map[string]struct{} {
	result := make(map[string]struct{})
	for _, group := range groups {
		if group.resource.Deleted || !matchesPrefixes(group.name, prefixes) {
			continue
		}
		for _, memberID := range group.members {
			result[memberID] = struct{}{}
		}
	}
	return result
}

func containsUser(users map[string]struct{}, userID string) bool {
	_, ok := users[userID]
	return ok
}

func matchesPrefixes(value string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	value = strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

func memberIDs(value any) []string {
	values := interfaceSlice(value)
	result := make([]string, 0, len(values))
	for _, item := range values {
		itemMap, ok := stringMap(item)
		if !ok {
			continue
		}
		memberID, _ := itemMap["value"].(string)
		memberID = strings.TrimSpace(memberID)
		if memberID != "" && !slices.Contains(result, memberID) {
			result = append(result, memberID)
		}
	}
	return result
}

func userEmail(attributes scimlib.ResourceAttributes) string {
	var fallback string
	for _, item := range interfaceSlice(attributes["emails"]) {
		itemMap, ok := stringMap(item)
		if !ok {
			continue
		}
		value, _ := itemMap["value"].(string)
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if fallback == "" {
			fallback = value
		}
		if primary, _ := itemMap["primary"].(bool); primary {
			return value
		}
	}
	if fallback != "" {
		return fallback
	}
	userName := attributeString(attributes, "userName")
	if strings.Contains(userName, "@") {
		return userName
	}
	return ""
}

func userDisplayName(attributes scimlib.ResourceAttributes) string {
	if displayName := attributeString(attributes, "displayName"); displayName != "" {
		return displayName
	}
	name, ok := stringMap(attributes["name"])
	if ok {
		if formatted, _ := name["formatted"].(string); strings.TrimSpace(formatted) != "" {
			return strings.TrimSpace(formatted)
		}
		given, _ := name["givenName"].(string)
		family, _ := name["familyName"].(string)
		if combined := strings.TrimSpace(given + " " + family); combined != "" {
			return combined
		}
	}
	if email := userEmail(attributes); email != "" {
		return email
	}
	return attributeString(attributes, "userName")
}

func attributeBool(attributes scimlib.ResourceAttributes, name string, fallback bool) bool {
	value, ok := attributes[name]
	if !ok {
		return fallback
	}
	result, ok := value.(bool)
	if !ok {
		return fallback
	}
	return result
}
