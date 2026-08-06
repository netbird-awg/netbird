package tunnel

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	clienttunnel "github.com/netbirdio/netbird/client/iface/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
)

// PrepareSettingsUpdate validates and timestamps a tunnel settings update.
func PrepareSettingsUpdate(
	updated,
	current *types.Settings,
	now time.Time,
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

	profileChanged, err := prepareProfileUpdate(updated, current, now)
	if err != nil {
		return false, err
	}
	if updated.TunnelPolicy == types.TunnelAccountPolicyRequireAWG &&
		updated.TunnelProfile == nil {
		return false, errors.New("required AWG policy needs a tunnel profile")
	}
	return policyChanged || profileChanged, nil
}

func prepareProfileUpdate(
	updated,
	current *types.Settings,
	now time.Time,
) (bool, error) {
	if updated.TunnelProfile == nil {
		updated.TunnelProfile = cloneProfile(current.TunnelProfile)
		return false, nil
	}
	profile := updated.TunnelProfile
	if _, err := clienttunnel.DecodeProfile(
		profile.ProtocolVersion,
		profile.Revision,
		profile.Parameters,
	); err != nil {
		return false, fmt.Errorf("validate tunnel profile: %w", err)
	}
	if current.TunnelProfile == nil {
		profile.UpdatedAt = now
		return true, nil
	}

	currentProfile := current.TunnelProfile
	sameRevision := profile.Revision == currentProfile.Revision
	sameContents := profile.ProtocolVersion == currentProfile.ProtocolVersion &&
		bytes.Equal(profile.Parameters, currentProfile.Parameters)
	if sameRevision && sameContents {
		profile.UpdatedAt = currentProfile.UpdatedAt
		return false, nil
	}
	return false, errors.New(
		"tunnel profile rotation is not supported; create a new account profile",
	)
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
	if profile == nil {
		return nil
	}
	return &types.TunnelProfile{
		ProtocolVersion: profile.ProtocolVersion,
		Revision:        profile.Revision,
		Parameters:      slices.Clone(profile.Parameters),
		UpdatedAt:       profile.UpdatedAt,
	}
}
