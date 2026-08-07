package tunnel

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	clienttunnel "github.com/netbirdio/netbird/client/iface/tunnel"
	"github.com/netbirdio/netbird/management/server/types"
	sharedtypes "github.com/netbirdio/netbird/shared/management/types"
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

func TestPrepareSettingsUpdateStagesProfileRotation(t *testing.T) {
	now := time.Now().UTC()
	current := &types.Settings{
		TunnelPolicy:  types.TunnelAccountPolicyPreferAWG,
		TunnelProfile: validTunnelProfile(4, now.Add(-time.Hour)),
	}
	updated := &types.Settings{
		TunnelProfile: validTunnelProfile(5, time.Time{}),
	}

	changed, err := PrepareSettingsUpdate(updated, current, now)
	if err != nil {
		t.Fatalf("rotate profile: %v", err)
	}
	if !changed {
		t.Fatal("profile rotation was not reported as changed")
	}
	if updated.TunnelProfile == nil || updated.TunnelProfile.Revision != 4 {
		t.Fatalf("active profile changed before activation: %+v", updated)
	}
	if updated.TunnelProfilePending == nil ||
		updated.TunnelProfilePending.Revision != 5 ||
		!updated.TunnelProfilePending.UpdatedAt.Equal(now) {
		t.Fatalf("profile was not staged: %+v", updated)
	}
}

func TestPrepareSettingsUpdateRejectsNonIncreasingRevision(t *testing.T) {
	now := time.Now().UTC()
	current := &types.Settings{
		TunnelProfile: validTunnelProfile(4, now.Add(-time.Hour)),
	}
	updated := &types.Settings{
		TunnelProfile: validTunnelProfile(4, time.Time{}),
	}
	updated.TunnelProfile.Parameters = json.RawMessage(
		`{"h1":"111","h2":"112","h3":"113","h4":"114"}`,
	)

	if _, err := PrepareSettingsUpdate(updated, current, now); err == nil {
		t.Fatal("changed profile with a reused revision was accepted")
	}
}

func TestPrepareSettingsUpdateGeneratesAWG3Secret(t *testing.T) {
	now := time.Now().UTC()
	profile := validAWG3TunnelProfile(1, time.Time{})
	callerParameters := bytes.Clone(profile.Parameters)
	profile.HeaderProtectionKey = bytes.Repeat([]byte{0xff}, 32)
	updated := &types.Settings{TunnelProfile: profile}

	changed, err := PrepareSettingsUpdate(updated, &types.Settings{}, now)
	if err != nil {
		t.Fatalf("prepare AWG3 profile: %v", err)
	}
	if !changed {
		t.Fatal("new AWG3 profile was not reported as changed")
	}
	staged := updated.TunnelProfilePending
	if staged == nil {
		t.Fatal("AWG3 profile was not staged")
	}
	if len(staged.HeaderProtectionKey) != 32 {
		t.Fatalf("generated key length = %d", len(staged.HeaderProtectionKey))
	}
	if bytes.Equal(
		staged.HeaderProtectionKey,
		bytes.Repeat([]byte{0xff}, 32),
	) {
		t.Fatal("caller-supplied AWG3 key was accepted")
	}
	if bytes.Equal(staged.Parameters, callerParameters) {
		t.Fatal("caller-supplied AWG3 parameters were accepted")
	}
}

func TestPrepareSettingsUpdateGeneratesBaseParametersOnManagement(t *testing.T) {
	updated := &types.Settings{
		TunnelProfile: &types.TunnelProfile{
			ProtocolVersion: clienttunnel.ProtocolAmneziaWG3,
			Revision:        1,
			Parameters:      json.RawMessage(`{}`),
		},
	}

	_, err := PrepareSettingsUpdate(
		updated,
		&types.Settings{},
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("generate AWG3 profile: %v", err)
	}
	staged := updated.TunnelProfilePending
	if staged == nil {
		t.Fatal("generated profile was not staged")
	}
	decoded, err := clienttunnel.DecodeProfileWithHeaderKey(
		staged.ProtocolVersion,
		staged.Revision,
		staged.Parameters,
		staged.HeaderProtectionKey,
	)
	if err != nil {
		t.Fatalf("decode generated profile: %v", err)
	}
	if decoded.AWG3.ContentPaddingAddition == "" {
		t.Fatal("generated AWG3 parameters are incomplete")
	}
}

func TestPrepareSettingsUpdatePreservesAWG3SecretForSameRevision(t *testing.T) {
	now := time.Now().UTC()
	currentProfile := validAWG3TunnelProfile(3, now.Add(-time.Hour))
	currentProfile.HeaderProtectionKey = bytes.Repeat([]byte{0x42}, 32)
	current := &types.Settings{TunnelProfile: currentProfile}
	updated := &types.Settings{
		TunnelProfile: validAWG3TunnelProfile(3, time.Time{}),
	}

	changed, err := PrepareSettingsUpdate(updated, current, now)
	if err != nil {
		t.Fatalf("prepare unchanged AWG3 profile: %v", err)
	}
	if changed {
		t.Fatal("unchanged AWG3 profile was reported as changed")
	}
	if !bytes.Equal(
		updated.TunnelProfile.HeaderProtectionKey,
		currentProfile.HeaderProtectionKey,
	) {
		t.Fatal("unchanged AWG3 profile did not preserve its key")
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

func TestPrepareSettingsUpdateActivatesReadyPendingProfile(t *testing.T) {
	now := time.Now().UTC()
	currentProfile := validTunnelProfile(6, now.Add(-time.Hour))
	pendingProfile := validAWG3TunnelProfile(7, now.Add(-time.Minute))
	pendingProfile.HeaderProtectionKey = bytes.Repeat([]byte{0x42}, 32)
	current := &types.Settings{
		TunnelProfile:        currentProfile,
		TunnelProfilePending: pendingProfile,
	}
	updated := &types.Settings{
		TunnelProfileAction: types.TunnelProfileActionActivate,
	}
	peer := plannerAWG3Peer("ready", now.Add(-time.Minute))

	changed, err := PrepareSettingsUpdate(
		updated,
		current,
		now,
		[]*sharedtypes.ComponentPeer{peer},
	)
	if err != nil {
		t.Fatalf("activate pending profile: %v", err)
	}
	if !changed ||
		updated.TunnelProfile == nil ||
		updated.TunnelProfile.Revision != 7 ||
		updated.TunnelProfilePending != nil ||
		updated.TunnelProfilePrevious == nil ||
		updated.TunnelProfilePrevious.Revision != 6 {
		t.Fatalf("unexpected activated state: %+v", updated)
	}
	if !updated.TunnelProfileGraceUntil.Equal(
		now.Add(tunnelProfileRollbackGrace),
	) {
		t.Fatalf(
			"rollback grace = %s",
			updated.TunnelProfileGraceUntil,
		)
	}
}

func TestPrepareSettingsUpdateRejectsActivationBeforeReady(t *testing.T) {
	now := time.Now().UTC()
	pendingProfile := validAWG3TunnelProfile(7, now.Add(-time.Minute))
	pendingProfile.HeaderProtectionKey = bytes.Repeat([]byte{0x42}, 32)
	current := &types.Settings{
		TunnelProfilePending: pendingProfile,
	}
	updated := &types.Settings{
		TunnelProfileAction: types.TunnelProfileActionActivate,
	}
	peer := plannerAWG3Peer("stale", now.Add(-time.Minute))
	peer.TunnelRuntime.ProfileRevision = 6

	if _, err := PrepareSettingsUpdate(
		updated,
		current,
		now,
		[]*sharedtypes.ComponentPeer{peer},
	); err == nil {
		t.Fatal("stale peer allowed profile activation")
	}
}

func TestPrepareSettingsUpdateStagesRollbackDuringGrace(t *testing.T) {
	now := time.Now().UTC()
	current := &types.Settings{
		TunnelProfile:           validAWG3TunnelProfile(7, now.Add(-time.Hour)),
		TunnelProfilePrevious:   validTunnelProfile(6, now.Add(-2*time.Hour)),
		TunnelProfileGraceUntil: now.Add(time.Hour),
	}
	current.TunnelProfile.HeaderProtectionKey = bytes.Repeat([]byte{0x42}, 32)
	updated := &types.Settings{
		TunnelProfileAction: types.TunnelProfileActionRollback,
	}

	changed, err := PrepareSettingsUpdate(updated, current, now)
	if err != nil {
		t.Fatalf("stage rollback: %v", err)
	}
	if !changed ||
		updated.TunnelProfile == nil ||
		updated.TunnelProfile.Revision != 7 ||
		updated.TunnelProfilePending == nil ||
		updated.TunnelProfilePending.Revision != 6 {
		t.Fatalf("unexpected rollback state: %+v", updated)
	}
}

func TestPrepareSettingsUpdateClearsExpiredRollbackProfile(t *testing.T) {
	now := time.Now().UTC()
	current := &types.Settings{
		TunnelProfile:           validAWG3TunnelProfile(7, now.Add(-time.Hour)),
		TunnelProfilePrevious:   validTunnelProfile(6, now.Add(-2*time.Hour)),
		TunnelProfileGraceUntil: now.Add(-time.Minute),
	}
	current.TunnelProfile.HeaderProtectionKey = bytes.Repeat([]byte{0x42}, 32)
	updated := &types.Settings{}

	changed, err := PrepareSettingsUpdate(updated, current, now)
	if err != nil {
		t.Fatalf("clear expired rollback profile: %v", err)
	}
	if !changed {
		t.Fatal("expired rollback profile removal was not reported as changed")
	}
	if updated.TunnelProfilePrevious != nil ||
		!updated.TunnelProfileGraceUntil.IsZero() {
		t.Fatalf("expired rollback profile was retained: %+v", updated)
	}
}

func TestPrepareSettingsUpdateUsesPreviousRevisionForRotationFloor(
	t *testing.T,
) {
	now := time.Now().UTC()
	current := &types.Settings{
		TunnelProfile:           validTunnelProfile(6, now.Add(-time.Hour)),
		TunnelProfilePrevious:   validAWG3TunnelProfile(7, now.Add(-2*time.Hour)),
		TunnelProfileGraceUntil: now.Add(time.Hour),
	}
	current.TunnelProfilePrevious.HeaderProtectionKey =
		bytes.Repeat([]byte{0x42}, 32)
	updated := &types.Settings{
		TunnelProfile: validTunnelProfile(7, time.Time{}),
	}

	if _, err := PrepareSettingsUpdate(updated, current, now); err == nil {
		t.Fatal("rotation reused a revision retained for rollback")
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

func validAWG3TunnelProfile(
	revision uint64,
	updatedAt time.Time,
) *types.TunnelProfile {
	return &types.TunnelProfile{
		ProtocolVersion: clienttunnel.ProtocolAmneziaWG3,
		Revision:        revision,
		Parameters: json.RawMessage(
			`{"s1":12,"s2":12,"s3":12,"s4":12,` +
				`"h1":"101","h2":"102","h3":"103","h4":"104",` +
				`"content_padding_addition":"1-16",` +
				`"persistent_keepalive_interval":"20-30"}`,
		),
		UpdatedAt: updatedAt,
	}
}
