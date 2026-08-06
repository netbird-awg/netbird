package tunnel

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/server/types"
)

func TestPrepareSettingsUpdatePreservesOmittedTunnelFields(t *testing.T) {
	now := time.Now().UTC()
	current := &types.Settings{
		TunnelPolicy:          types.TunnelAccountPolicyPreferAWG,
		TunnelPolicyUpdatedAt: now.Add(-time.Hour),
		TunnelProfile:         validTunnelProfile(4, now.Add(-time.Hour)),
	}
	updated := &types.Settings{}

	changed, err := PrepareSettingsUpdate(updated, current, now)
	if err != nil {
		t.Fatalf("prepare settings update: %v", err)
	}
	if changed {
		t.Fatal("omitted tunnel fields were reported as changed")
	}
	if updated.TunnelPolicy != current.TunnelPolicy ||
		updated.TunnelProfile == nil ||
		updated.TunnelProfile.Revision != current.TunnelProfile.Revision {
		t.Fatalf("tunnel fields were not preserved: %+v", updated)
	}
}

func TestPrepareSettingsUpdateRejectsProfileRotation(t *testing.T) {
	now := time.Now().UTC()
	current := &types.Settings{
		TunnelPolicy:  types.TunnelAccountPolicyPreferAWG,
		TunnelProfile: validTunnelProfile(4, now.Add(-time.Hour)),
	}
	updated := &types.Settings{
		TunnelProfile: validTunnelProfile(5, time.Time{}),
	}

	if _, err := PrepareSettingsUpdate(updated, current, now); err == nil {
		t.Fatal("profile rotation was accepted")
	}
}

func TestPrepareSettingsUpdateRejectsUnsafeParameters(t *testing.T) {
	now := time.Now().UTC()
	updated := &types.Settings{
		TunnelProfile: validTunnelProfile(1, time.Time{}),
	}
	updated.TunnelProfile.Parameters = json.RawMessage(
		"{\"h1\":\"101\\nprivate_key=00\",\"h2\":\"102\"," +
			"\"h3\":\"103\",\"h4\":\"104\"}",
	)

	if _, err := PrepareSettingsUpdate(updated, &types.Settings{}, now); err == nil {
		t.Fatal("profile containing a UAPI line break was accepted")
	}
}

func TestPrepareSettingsUpdateRequireAWGNeedsProfile(t *testing.T) {
	updated := &types.Settings{
		TunnelPolicy: types.TunnelAccountPolicyRequireAWG,
	}

	if _, err := PrepareSettingsUpdate(
		updated,
		&types.Settings{},
		time.Now().UTC(),
	); err == nil {
		t.Fatal("required AWG policy without a profile was accepted")
	}
}

func validTunnelProfile(revision uint64, updatedAt time.Time) *types.TunnelProfile {
	return &types.TunnelProfile{
		ProtocolVersion: "awg2",
		Revision:        revision,
		Parameters: json.RawMessage(
			`{"h1":"101","h2":"102","h3":"103","h4":"104"}`,
		),
		UpdatedAt: updatedAt,
	}
}
