package bind

import (
	"net/netip"
	"testing"
	"time"

	"github.com/netbirdio/netbird/monotime"
)

func TestActivityRecorder_GetLastActivities(t *testing.T) {
	peer := "peer1"
	ar := NewActivityRecorder()
	ar.UpsertAddress("peer1", netip.MustParseAddrPort("192.168.0.5:51820"))
	activities := ar.GetLastActivities()

	p, ok := activities[peer]
	if !ok {
		t.Fatalf("Expected activity for peer %s, but got none", peer)
	}

	if monotime.Since(p) > 5*time.Second {
		t.Fatalf("Expected activity for peer %s to be recent, but got %v", peer, p)
	}
}

func TestActivityRecorderAuthenticatedEventsIgnoreRawPackets(t *testing.T) {
	const peer = "peer1"
	address := netip.MustParseAddrPort("192.168.0.5:51820")
	recorder := NewActivityRecorder()
	recorder.UpsertAddress(peer, address)
	recorder.peers[peer].LastActivity.Store(0)
	recorder.UseAuthenticatedEvents()

	recorder.record(address)
	if got := recorder.peers[peer].LastActivity.Load(); got != 0 {
		t.Fatalf("unauthenticated packet updated activity to %d", got)
	}

	recorder.RecordPeer(peer)
	if got := recorder.peers[peer].LastActivity.Load(); got == 0 {
		t.Fatal("authenticated packet did not update activity")
	}
}
