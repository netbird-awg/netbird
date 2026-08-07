package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	clienttunnel "github.com/netbirdio/netbird/client/iface/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
)

const tunnelProfileRollbackGrace = 24 * time.Hour

// PrepareSettingsUpdate validates and timestamps a tunnel settings update.
func PrepareSettingsUpdate(
	updated,
	current *types.Settings,
	now time.Time,
	peerGroups ...[]*sharedtypes.ComponentPeer,
) (bool, error) {
	if updated == nil || current == nil {
		return false, errors.New("tunnel settings are nil")
	}

	currentPolicy := normalizeAccountPolicy(current.TunnelPolicy)
	if updated.TunnelPolicy == "" {
		updated.TunnelPolicy = currentPolicy
	}
	if !validAccountPolicy(updated.TunnelPolicy) {
		return false, fmt.Errorf(
			"unsupported tunnel policy %q",
			updated.TunnelPolicy,
		)
	}

	policyChanged := updated.TunnelPolicy != currentPolicy
	if policyChanged {
		updated.TunnelPolicyUpdatedAt = now
	} else {
		updated.TunnelPolicyUpdatedAt = current.TunnelPolicyUpdatedAt
	}

	var peers []*sharedtypes.ComponentPeer
	if len(peerGroups) > 0 {
		peers = peerGroups[0]
	}
	profileChanged, err := prepareProfileUpdate(
		updated,
		current,
		peers,
		now,
	)
	if err != nil {
		return false, err
	}
	if updated.TunnelPolicy == types.TunnelAccountPolicyRequireAWG &&
		updated.TunnelProfile == nil &&
		updated.TunnelProfilePending == nil {
		return false, errors.New("required AWG policy needs a tunnel profile")
	}
	return policyChanged || profileChanged, nil
}

func prepareProfileUpdate(
	updated,
	current *types.Settings,
	peers []*sharedtypes.ComponentPeer,
	now time.Time,
) (bool, error) {
	expiredPreviousCleared := false
	updated.TunnelProfilePending = cloneProfile(
		current.TunnelProfilePending,
	)
	updated.TunnelProfilePrevious = cloneProfile(
		current.TunnelProfilePrevious,
	)
	updated.TunnelProfileGraceUntil = current.TunnelProfileGraceUntil
	if updated.TunnelProfilePrevious != nil &&
		(updated.TunnelProfileGraceUntil.IsZero() ||
			!updated.TunnelProfileGraceUntil.After(now)) {
		updated.TunnelProfilePrevious = nil
		updated.TunnelProfileGraceUntil = time.Time{}
		expiredPreviousCleared = true
	}

	var changed bool
	var err error
	switch updated.TunnelProfileAction {
	case "":
		changed, err = stageProfileUpdate(updated, current, now)
	case types.TunnelProfileActionActivate:
		changed, err = activatePendingProfile(updated, current, peers, now)
	case types.TunnelProfileActionRollback:
		changed, err = stageProfileRollback(updated, current, now)
	default:
		return false, fmt.Errorf(
			"unsupported tunnel profile action %q",
			updated.TunnelProfileAction,
		)
	}
	return changed || expiredPreviousCleared, err
}

func stageProfileUpdate(
	updated,
	current *types.Settings,
	now time.Time,
) (bool, error) {
	requested := updated.TunnelProfile
	currentProfile := current.TunnelProfile
	if requested == nil {
		updated.TunnelProfile = cloneProfile(currentProfile)
		return false, nil
	}
	if sameProfileRevisionAndContents(requested, currentProfile) {
		updated.TunnelProfile = cloneProfile(currentProfile)
		return false, nil
	}
	if sameProfileRevisionAndContents(
		requested,
		current.TunnelProfilePending,
	) {
		updated.TunnelProfile = cloneProfile(currentProfile)
		return false, nil
	}

	highestRevision := uint64(0)
	for _, profile := range []*types.TunnelProfile{
		currentProfile,
		current.TunnelProfilePending,
		current.TunnelProfilePrevious,
	} {
		if profile != nil && profile.Revision > highestRevision {
			highestRevision = profile.Revision
		}
	}
	if requested.Revision <= highestRevision {
		return false, fmt.Errorf(
			"tunnel profile revision must increase from %d",
			highestRevision,
		)
	}
	profile := requested.Copy()
	if profile.ProtocolVersion == clienttunnel.ProtocolAmneziaWG3 ||
		profileParametersMissing(profile.Parameters) {
		parameters, err := generateProfileParameters(profile.ProtocolVersion)
		if err != nil {
			return false, err
		}
		profile.Parameters = parameters
	}
	if err := assignProfileSecret(profile); err != nil {
		return false, err
	}
	if err := validateProfile(profile); err != nil {
		return false, err
	}
	profile.UpdatedAt = now
	updated.TunnelProfile = cloneProfile(currentProfile)
	updated.TunnelProfilePending = profile
	updated.TunnelProfileAction = ""
	return true, nil
}

func activatePendingProfile(
	updated,
	current *types.Settings,
	peers []*sharedtypes.ComponentPeer,
	now time.Time,
) (bool, error) {
	pending := current.TunnelProfilePending
	if pending == nil {
		return false, errors.New("no pending tunnel profile to activate")
	}
	if err := validatePendingReadiness(pending, peers); err != nil {
		return false, err
	}

	updated.TunnelProfile = cloneProfile(pending)
	updated.TunnelProfilePending = nil
	updated.TunnelProfilePrevious = cloneProfile(current.TunnelProfile)
	if updated.TunnelProfilePrevious != nil {
		updated.TunnelProfileGraceUntil = now.Add(
			tunnelProfileRollbackGrace,
		)
	} else {
		updated.TunnelProfileGraceUntil = time.Time{}
	}
	updated.TunnelProfileAction = ""
	return true, nil
}

func stageProfileRollback(
	updated,
	current *types.Settings,
	now time.Time,
) (bool, error) {
	if current.TunnelProfilePrevious == nil {
		return false, errors.New("no previous tunnel profile to restore")
	}
	if current.TunnelProfileGraceUntil.IsZero() ||
		!current.TunnelProfileGraceUntil.After(now) {
		return false, errors.New("tunnel profile rollback grace period expired")
	}

	updated.TunnelProfile = cloneProfile(current.TunnelProfile)
	updated.TunnelProfilePending = cloneProfile(
		current.TunnelProfilePrevious,
	)
	updated.TunnelProfilePending.UpdatedAt = now
	updated.TunnelProfileAction = ""
	return true, nil
}

func validatePendingReadiness(
	profile *types.TunnelProfile,
	peers []*sharedtypes.ComponentPeer,
) error {
	for _, peer := range peers {
		if peer == nil || assignedProtocol(peer, profile) == "" {
			continue
		}
		state := plannerPeerState(peer, UserPolicyInherit, profile)
		if !state.Ready {
			return fmt.Errorf(
				"peer %s has not acknowledged the pending tunnel profile",
				peerIdentity(peer),
			)
		}
		if reason := configurationMismatchReason(state, state); reason != "" {
			return fmt.Errorf(
				"peer %s is not ready for activation: %s",
				peerIdentity(peer),
				reason,
			)
		}
	}
	return nil
}

func normalizeAccountPolicy(
	policy types.TunnelAccountPolicy,
) types.TunnelAccountPolicy {
	if policy == "" {
		return types.TunnelAccountPolicyStandard
	}
	return policy
}

func validAccountPolicy(policy types.TunnelAccountPolicy) bool {
	switch policy {
	case types.TunnelAccountPolicyStandard,
		types.TunnelAccountPolicyPreferAWG,
		types.TunnelAccountPolicyRequireAWG:
		return true
	default:
		return false
	}
}

func cloneProfile(profile *types.TunnelProfile) *types.TunnelProfile {
	return profile.Copy()
}

func sameProfileContents(left, right *types.TunnelProfile) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.ProtocolVersion == right.ProtocolVersion &&
		bytes.Equal(left.Parameters, right.Parameters)
}

func sameProfileRevisionAndContents(
	left,
	right *types.TunnelProfile,
) bool {
	return left != nil &&
		right != nil &&
		left.Revision == right.Revision &&
		sameProfileContents(left, right)
}

func profileParametersMissing(parameters json.RawMessage) bool {
	var value map[string]json.RawMessage
	return len(bytes.TrimSpace(parameters)) == 0 ||
		json.Unmarshal(parameters, &value) == nil && len(value) == 0
}

func assignProfileSecret(profile *types.TunnelProfile) error {
	profile.EncryptedHeaderProtectionKey = ""
	profile.HeaderProtectionKey = nil
	if profile.ProtocolVersion != clienttunnel.ProtocolAmneziaWG3 {
		return nil
	}

	profile.HeaderProtectionKey = make([]byte, 32)
	if _, err := rand.Read(profile.HeaderProtectionKey); err != nil {
		return fmt.Errorf("generate AWG3 header protection key: %w", err)
	}
	return nil
}

type generatedAWG3Parameters struct {
	clienttunnel.AWG2Parameters
	clienttunnel.AWG3Parameters
}

func generateProfileParameters(protocolVersion string) (json.RawMessage, error) {
	headers, err := randomHeaders(4)
	if err != nil {
		return nil, err
	}
	junkMin, err := randomInteger(48, 96)
	if err != nil {
		return nil, err
	}
	junkMax, err := randomInteger(junkMin, min(junkMin+192, 512))
	if err != nil {
		return nil, err
	}
	junkCount, err := randomInteger(3, 8)
	if err != nil {
		return nil, err
	}
	s1, err := randomInteger(12, 48)
	if err != nil {
		return nil, err
	}
	s2, err := randomInteger(12, 48)
	if err != nil {
		return nil, err
	}
	s3, err := randomInteger(12, 48)
	if err != nil {
		return nil, err
	}
	s4, err := randomInteger(12, 24)
	if err != nil {
		return nil, err
	}

	base := clienttunnel.AWG2Parameters{
		JunkPacketCount:   junkCount,
		JunkPacketMin:     junkMin,
		JunkPacketMax:     junkMax,
		InitiationPadding: s1,
		ResponsePadding:   s2,
		CookiePadding:     s3,
		TransportPadding:  s4,
		InitiationHeader:  fmt.Sprint(headers[0]),
		ResponseHeader:    fmt.Sprint(headers[1]),
		CookieHeader:      fmt.Sprint(headers[2]),
		TransportHeader:   fmt.Sprint(headers[3]),
	}

	var parameters any = base
	switch protocolVersion {
	case clienttunnel.ProtocolAmneziaWG2:
	case clienttunnel.ProtocolAmneziaWG3:
		parameters = generatedAWG3Parameters{
			AWG2Parameters: base,
			AWG3Parameters: clienttunnel.AWG3Parameters{
				ContentPaddingAddition:      "1-8",
				PersistentKeepaliveInterval: "20-30",
				RekeyAfterTime:              "90-120",
				RekeyTimeout:                "3-5",
				RejectAfterTime:             "180-240",
				KeepaliveTimeout:            "8-12",
				MaxHandshakeAttempts:        "18-24",
			},
		}
	default:
		return nil, fmt.Errorf(
			"unsupported tunnel protocol %q",
			protocolVersion,
		)
	}

	raw, err := json.Marshal(parameters)
	if err != nil {
		return nil, fmt.Errorf("encode generated tunnel profile: %w", err)
	}
	return raw, nil
}

func randomHeaders(count int) ([]uint32, error) {
	headers := make([]uint32, 0, count)
	seen := make(map[uint32]struct{}, count)
	for len(headers) < count {
		value, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 32))
		if err != nil {
			return nil, fmt.Errorf("generate tunnel header: %w", err)
		}
		header := uint32(value.Uint64())
		if header <= 4 {
			continue
		}
		if _, ok := seen[header]; ok {
			continue
		}
		seen[header] = struct{}{}
		headers = append(headers, header)
	}
	return headers, nil
}

func randomInteger(minimum, maximum int) (int, error) {
	value, err := rand.Int(
		rand.Reader,
		big.NewInt(int64(maximum-minimum+1)),
	)
	if err != nil {
		return 0, fmt.Errorf("generate tunnel parameter: %w", err)
	}
	return minimum + int(value.Int64()), nil
}

func validateProfile(profile *types.TunnelProfile) error {
	if _, err := clienttunnel.DecodeProfileWithHeaderKey(
		profile.ProtocolVersion,
		profile.Revision,
		profile.Parameters,
		profile.HeaderProtectionKey,
	); err != nil {
		return fmt.Errorf("validate tunnel profile: %w", err)
	}
	return nil
}
