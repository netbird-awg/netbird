package edr

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	edrmodel "github.com/netbirdio/netbird/management/server/localintegrations/edr/model"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	api "github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/management/status"
)

type peerDecision struct {
	inScope   bool
	compliant bool
	bypassed  bool
	reason    string
}

func (s *Service) ValidateExtraSettings(
	ctx context.Context,
	newExtraSettings *types.ExtraSettings,
	_ *types.ExtraSettings,
	_ string,
	accountID string,
) error {
	if newExtraSettings == nil {
		return nil
	}
	requested := newExtraSettings.IntegratedValidator
	if requested != "" && !slices.Contains(providers, requested) {
		return status.Errorf(status.InvalidArgument, "unsupported integrated validator")
	}
	integration, err := s.repository.getEnabledIntegration(ctx, accountID)
	if err != nil {
		return err
	}
	if integration == nil {
		if requested == "" {
			return nil
		}
		return status.Errorf(status.InvalidArgument, "no matching EDR integration is enabled")
	}
	if requested == "" {
		return status.Errorf(status.PreconditionFailed, "disable EDR from the MDM & EDR integration page")
	}
	if integration.Provider != requested {
		return status.Errorf(status.InvalidArgument, "enabled EDR integration does not match account settings")
	}
	requestedGroups := slices.Clone(newExtraSettings.IntegratedValidatorGroups)
	slices.Sort(requestedGroups)
	if !slices.Equal(requestedGroups, integration.Groups) {
		return status.Errorf(status.PreconditionFailed, "update EDR groups from the MDM & EDR integration page")
	}
	return nil
}

func (s *Service) ValidatePeer(
	ctx context.Context,
	update *nbpeer.Peer,
	peer *nbpeer.Peer,
	_ string,
	accountID string,
	_ string,
	peerGroups []string,
	_ *types.ExtraSettings,
) (*nbpeer.Peer, bool, error) {
	candidate := peer.Copy()
	candidate.Name = update.Name
	decision, err := s.evaluatePeer(ctx, accountID, candidate, peerGroups, true)
	if err != nil {
		return nil, false, err
	}
	requiresApproval := decision.inScope && !decision.compliant && !decision.bypassed
	changed := candidate.Status != nil && candidate.Status.RequiresApproval != requiresApproval
	return update, changed, nil
}

func (s *Service) PreparePeer(
	ctx context.Context,
	accountID string,
	peer *nbpeer.Peer,
	peerGroups []string,
	_ *types.ExtraSettings,
	_ bool,
) *nbpeer.Peer {
	result := peer.Copy()
	if result.Status == nil {
		result.Status = &nbpeer.PeerStatus{}
	}
	decision, err := s.evaluatePeer(ctx, accountID, result, peerGroups, true)
	if err != nil {
		// A configured validator must fail closed while the database is
		// unavailable. Peers outside the configured groups are handled by the
		// successful path and remain unaffected.
		result.Status.RequiresApproval = true
		return result
	}
	result.Status.RequiresApproval = decision.inScope && !decision.compliant && !decision.bypassed
	return result
}

func (s *Service) IsNotValidPeer(
	ctx context.Context,
	accountID string,
	peer *nbpeer.Peer,
	peerGroups []string,
	_ *types.ExtraSettings,
) (bool, bool, error) {
	decision, err := s.evaluatePeer(ctx, accountID, peer, peerGroups, true)
	if err != nil {
		return false, false, err
	}
	notValid := decision.inScope && !decision.compliant && !decision.bypassed
	changed := peer.Status != nil && peer.Status.RequiresApproval != notValid
	return notValid, changed, nil
}

func (s *Service) GetValidatedPeers(
	ctx context.Context,
	accountID string,
	groups []*types.Group,
	peers []*nbpeer.Peer,
	_ *types.ExtraSettings,
) (map[string]struct{}, error) {
	valid, _, err := s.evaluatePeers(ctx, accountID, groups, peers)
	return valid, err
}

func (s *Service) GetPeerValidationResults(
	ctx context.Context,
	accountID string,
	groups []*types.Group,
	peers []*nbpeer.Peer,
	_ *types.ExtraSettings,
) (map[string]struct{}, map[string]string, error) {
	return s.evaluatePeers(ctx, accountID, groups, peers)
}

func (s *Service) GetInvalidPeers(
	ctx context.Context,
	accountID string,
	_ *types.ExtraSettings,
) (map[string]string, error) {
	groups, err := s.store.GetAccountGroups(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}
	peers, err := s.store.GetAccountPeers(ctx, store.LockingStrengthNone, accountID, "", "")
	if err != nil {
		return nil, err
	}
	_, invalid, err := s.evaluatePeers(ctx, accountID, groups, peers)
	return invalid, err
}

func (s *Service) evaluatePeers(
	ctx context.Context,
	accountID string,
	groups []*types.Group,
	peers []*nbpeer.Peer,
) (map[string]struct{}, map[string]string, error) {
	valid := make(map[string]struct{}, len(peers))
	invalid := make(map[string]string)
	integration, err := s.repository.getEnabledIntegration(ctx, accountID)
	if err != nil {
		return nil, nil, err
	}
	if integration == nil {
		for _, peer := range peers {
			valid[peer.ID] = struct{}{}
		}
		return valid, invalid, nil
	}
	devices, err := s.repository.listDevices(ctx, integration.ID)
	if err != nil {
		return nil, nil, err
	}
	bypasses, err := s.repository.listBypasses(ctx, accountID)
	if err != nil {
		return nil, nil, err
	}
	serials, duplicateSerials := uniqueDeviceIndexes(devices, func(device edrmodel.Device) string {
		return device.SerialNumber
	})
	hostnames, duplicateHostnames := uniqueDeviceIndexes(devices, func(device edrmodel.Device) string {
		return device.Hostname
	})
	bypassSet := make(map[string]struct{}, len(bypasses))
	for _, bypass := range bypasses {
		bypassSet[bypass.PeerID] = struct{}{}
	}
	peerGroups := peerGroupMap(groups)
	if !s.snapshotFresh(integration.LastSyncedAt) {
		for _, peer := range peers {
			if !intersects(peerGroups[peer.ID], integration.Groups) {
				valid[peer.ID] = struct{}{}
				continue
			}
			if _, bypassed := bypassSet[peer.ID]; bypassed {
				valid[peer.ID] = struct{}{}
				continue
			}
			invalid[peer.ID] = providerDisplayName(integration.Provider) + " device data is stale"
		}
		return valid, invalid, nil
	}
	for _, peer := range peers {
		if !intersects(peerGroups[peer.ID], integration.Groups) {
			valid[peer.ID] = struct{}{}
			continue
		}
		var deviceIndex int
		var found bool
		if serial := normalizeIdentity(peer.Meta.SystemSerialNumber); serial != "" {
			if _, duplicate := duplicateSerials[serial]; duplicate {
				if _, bypassed := bypassSet[peer.ID]; bypassed {
					valid[peer.ID] = struct{}{}
				} else {
					invalid[peer.ID] = fmt.Sprintf("Device identity is ambiguous in %s", providerDisplayName(integration.Provider))
				}
				continue
			}
			deviceIndex, found = serials[serial]
		}
		if !found {
			hostname := normalizeIdentity(firstNonEmpty(peer.Meta.Hostname, peer.Name))
			if _, duplicate := duplicateHostnames[hostname]; duplicate {
				if _, bypassed := bypassSet[peer.ID]; bypassed {
					valid[peer.ID] = struct{}{}
				} else {
					invalid[peer.ID] = fmt.Sprintf("Device identity is ambiguous in %s", providerDisplayName(integration.Provider))
				}
				continue
			}
			deviceIndex, found = hostnames[hostname]
		}
		if !found {
			if _, bypassed := bypassSet[peer.ID]; bypassed {
				valid[peer.ID] = struct{}{}
			} else {
				invalid[peer.ID] = fmt.Sprintf("Device was not found in %s", providerDisplayName(integration.Provider))
			}
			continue
		}
		device := devices[deviceIndex]
		if device.Compliant {
			valid[peer.ID] = struct{}{}
			if _, bypassed := bypassSet[peer.ID]; bypassed {
				_ = s.repository.deleteBypass(ctx, accountID, peer.ID)
			}
			continue
		}
		if _, bypassed := bypassSet[peer.ID]; bypassed {
			valid[peer.ID] = struct{}{}
			continue
		}
		invalid[peer.ID] = firstNonEmpty(device.Reason, providerDisplayName(integration.Provider)+" device is not compliant")
	}
	return valid, invalid, nil
}

func (s *Service) evaluatePeer(
	ctx context.Context,
	accountID string,
	peer *nbpeer.Peer,
	peerGroups []string,
	honorBypass bool,
) (peerDecision, error) {
	integration, err := s.repository.getEnabledIntegration(ctx, accountID)
	if err != nil || integration == nil {
		return peerDecision{compliant: integration == nil}, err
	}
	if !intersects(peerGroups, integration.Groups) {
		return peerDecision{compliant: true}, nil
	}
	decision := peerDecision{inScope: true}
	if !s.snapshotFresh(integration.LastSyncedAt) {
		decision.reason = providerDisplayName(integration.Provider) + " device data is stale"
		if honorBypass {
			decision.bypassed, err = s.repository.hasBypass(ctx, accountID, peer.ID)
			if err != nil {
				return decision, status.Errorf(status.Internal, "failed to check EDR bypass")
			}
		}
		return decision, nil
	}
	device, err := s.repository.findDevice(
		ctx,
		integration.ID,
		normalizeIdentity(peer.Meta.SystemSerialNumber),
		normalizeIdentity(firstNonEmpty(peer.Meta.Hostname, peer.Name)),
	)
	if err != nil {
		return decision, err
	}
	if device == nil {
		decision.reason = fmt.Sprintf("Device was not found in %s", providerDisplayName(integration.Provider))
	} else if device.Compliant {
		decision.compliant = true
		if bypassed, bypassErr := s.repository.hasBypass(ctx, accountID, peer.ID); bypassErr == nil && bypassed {
			_ = s.repository.deleteBypass(ctx, accountID, peer.ID)
		}
		return decision, nil
	} else {
		decision.reason = firstNonEmpty(
			device.Reason,
			providerDisplayName(integration.Provider)+" device is not compliant",
		)
	}
	if honorBypass {
		decision.bypassed, err = s.repository.hasBypass(ctx, accountID, peer.ID)
		if err != nil {
			return decision, status.Errorf(status.Internal, "failed to check EDR bypass")
		}
	}
	return decision, nil
}

func (s *Service) BypassCompliance(
	ctx context.Context,
	accountID, userID, peerID string,
) (*api.BypassResponse, error) {
	ctx, err := s.requireBypassPermission(ctx, accountID, userID)
	if err != nil {
		return nil, err
	}
	peer, err := s.store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		return nil, err
	}
	groupIDs, err := s.store.GetPeerGroupIDs(ctx, store.LockingStrengthNone, accountID, peerID)
	if err != nil {
		return nil, err
	}
	decision, err := s.evaluatePeer(ctx, accountID, peer, groupIDs, false)
	if err != nil {
		return nil, err
	}
	if !decision.inScope || decision.compliant {
		return nil, status.Errorf(status.InvalidArgument, "peer is not in a non-compliant EDR state")
	}
	if err := s.repository.upsertBypass(ctx, &edrmodel.Bypass{
		AccountID: accountID,
		PeerID:    peerID,
		CreatedBy: userID,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		return nil, status.Errorf(status.Internal, "failed to bypass EDR compliance")
	}
	s.notifyPeerIDs(accountID, []string{peerID})
	return &api.BypassResponse{PeerId: peerID}, nil
}

func (s *Service) RevokeBypass(
	ctx context.Context,
	accountID, userID, peerID string,
) error {
	ctx, err := s.requireBypassPermission(ctx, accountID, userID)
	if err != nil {
		return err
	}
	if _, err := s.store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID); err != nil {
		return err
	}
	if err := s.repository.deleteBypass(ctx, accountID, peerID); err != nil {
		return status.Errorf(status.Internal, "failed to revoke EDR bypass")
	}
	s.notifyPeerIDs(accountID, []string{peerID})
	return nil
}

func (s *Service) ListBypassedPeers(
	ctx context.Context,
	accountID, userID string,
) ([]api.BypassResponse, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Read)
	if err != nil {
		return nil, err
	}
	bypasses, err := s.repository.listBypasses(ctx, accountID)
	if err != nil {
		return nil, err
	}
	result := make([]api.BypassResponse, 0, len(bypasses))
	for _, bypass := range bypasses {
		result = append(result, api.BypassResponse{PeerId: bypass.PeerID})
	}
	return result, nil
}

func (s *Service) requireBypassPermission(
	ctx context.Context,
	accountID, userID string,
) (context.Context, error) {
	ctx, err := s.requirePermission(ctx, accountID, userID, operations.Update)
	if err != nil {
		return ctx, err
	}
	ok, permissionCtx, err := s.permissions.ValidateUserPermissions(
		ctx,
		accountID,
		userID,
		modules.Peers,
		operations.Update,
	)
	if err != nil {
		return permissionCtx, status.NewPermissionValidationError(err)
	}
	if !ok {
		return permissionCtx, status.NewPermissionDeniedError()
	}
	return permissionCtx, nil
}

func (s *Service) PeerDeleted(
	ctx context.Context,
	accountID, peerID string,
	_ *types.ExtraSettings,
) error {
	return s.repository.deleteBypass(ctx, accountID, peerID)
}

func (s *Service) SetPeerInvalidationListener(listener func(accountID string, peerIDs []string)) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	s.listener = listener
}

func (s *Service) Stop(ctx context.Context) {
	s.stopWorker(ctx)
}

func (s *Service) ValidateFlowResponse(
	_ context.Context,
	_ string,
	flowResponse *proto.PKCEAuthorizationFlow,
) *proto.PKCEAuthorizationFlow {
	return flowResponse
}

func (s *Service) notifyPeers(ctx context.Context, accountID string, groups []string) {
	groups = uniqueStrings(groups)
	if len(groups) == 0 {
		return
	}
	notifyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	peerIDs, err := s.store.GetPeerIDsByGroups(notifyCtx, accountID, groups)
	if err != nil {
		log.WithContext(notifyCtx).
			WithError(err).
			Warnf("failed to resolve EDR peers for account %s", accountID)
		return
	}
	s.notifyPeerIDs(accountID, peerIDs)
}

func (s *Service) notifyPeerIDs(accountID string, peerIDs []string) {
	peerIDs = uniqueStrings(peerIDs)
	if len(peerIDs) == 0 {
		return
	}
	s.listenerMu.RLock()
	listener := s.listener
	s.listenerMu.RUnlock()
	if listener != nil {
		listener(accountID, peerIDs)
	}
}

func peerGroupMap(groups []*types.Group) map[string][]string {
	result := make(map[string][]string)
	for _, group := range groups {
		for _, peerID := range group.Peers {
			result[peerID] = append(result[peerID], group.ID)
		}
		for _, relation := range group.GroupPeers {
			result[relation.PeerID] = append(result[relation.PeerID], group.ID)
		}
	}
	return result
}

func uniqueDeviceIndexes(
	devices []edrmodel.Device,
	identity func(edrmodel.Device) string,
) (map[string]int, map[string]struct{}) {
	indexes := make(map[string]int, len(devices))
	duplicates := make(map[string]struct{})
	for index, device := range devices {
		value := identity(device)
		if value == "" {
			continue
		}
		if _, duplicate := duplicates[value]; duplicate {
			continue
		}
		if _, exists := indexes[value]; exists {
			delete(indexes, value)
			duplicates[value] = struct{}{}
			continue
		}
		indexes[value] = index
	}
	return indexes, duplicates
}

func intersects(left, right []string) bool {
	for _, value := range left {
		if slices.Contains(right, value) {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	slices.Sort(result)
	return result
}

func providerDisplayName(provider string) string {
	switch provider {
	case providerFalcon:
		return "CrowdStrike"
	case providerSentinelOne:
		return "SentinelOne"
	case providerFleetDM:
		return "FleetDM"
	case providerHuntress:
		return "Huntress"
	case providerIntune:
		return "Intune"
	default:
		return strings.ToUpper(provider)
	}
}

func (s *Service) snapshotFresh(lastSyncedAt *time.Time) bool {
	if lastSyncedAt == nil || lastSyncedAt.IsZero() {
		return false
	}
	now := time.Now().UTC()
	return !lastSyncedAt.After(now.Add(maxProviderClockSkew)) &&
		lastSyncedAt.After(now.Add(-s.cacheMaxAge))
}
