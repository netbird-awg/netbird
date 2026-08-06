package peer

import (
	"testing"
	"time"
)

func TestNormalizeTunnelRuntimeRecordsReadyRevision(t *testing.T) {
	now := time.Now().UTC()
	reported := TunnelRuntimeMeta{
		ProtocolVersion: "awg2",
		ProfileRevision: 7,
		AdapterRevision: "adapter",
		Ready:           true,
	}

	normalized := normalizeTunnelRuntime(TunnelRuntimeMeta{}, reported, now)

	if normalized.UpdatedAt != now ||
		normalized.LastReadyAt != now ||
		normalized.LastReadyProtocol != reported.ProtocolVersion ||
		normalized.LastReadyRevision != reported.ProfileRevision {
		t.Fatalf("ready revision was not recorded: %+v", normalized)
	}
}

func TestNormalizeTunnelRuntimePreservesLastReadyOnError(t *testing.T) {
	lastReadyAt := time.Now().UTC().Add(-time.Hour)
	current := TunnelRuntimeMeta{
		ProtocolVersion:   "awg2",
		ProfileRevision:   7,
		AdapterRevision:   "adapter",
		Ready:             true,
		UpdatedAt:         lastReadyAt,
		LastReadyProtocol: "awg2",
		LastReadyRevision: 7,
		LastReadyAt:       lastReadyAt,
	}
	now := time.Now().UTC()

	normalized := normalizeTunnelRuntime(
		current,
		TunnelRuntimeMeta{ErrorCode: "profile_invalid"},
		now,
	)

	if normalized.Ready ||
		normalized.UpdatedAt != now ||
		normalized.LastReadyAt != lastReadyAt ||
		normalized.LastReadyRevision != 7 {
		t.Fatalf("last ready state was not preserved: %+v", normalized)
	}
}

func TestNormalizeTunnelRuntimeKeepsTimestampForSameReport(t *testing.T) {
	updatedAt := time.Now().UTC().Add(-time.Hour)
	current := TunnelRuntimeMeta{
		ErrorCode: "profile_invalid",
		UpdatedAt: updatedAt,
	}

	normalized := normalizeTunnelRuntime(
		current,
		TunnelRuntimeMeta{ErrorCode: "profile_invalid"},
		time.Now().UTC(),
	)

	if normalized.UpdatedAt != updatedAt {
		t.Fatalf("unchanged report timestamp changed: %s", normalized.UpdatedAt)
	}
}
