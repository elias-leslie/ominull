package server

import (
	"path/filepath"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// The agent sends no SNI, so without borrowing the resolver's answer every
// finding quotes an edge address that will be a different one tomorrow.
func TestSnapshotNamesDestinationsFromResolver(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()

	if _, _, err := store.RecordDNSResolutions([]storage.DNSResolution{
		{Domain: "thumbnails-photos.amazon.com", IP: "10.9.9.9", At: now},
	}, now); err != nil {
		t.Fatalf("seeding resolution: %v", err)
	}

	events := []storage.Event{
		{EndpointID: "e1", TenantID: "t-01", DstIP: "10.9.9.9", DstPort: 443, Direction: "OUTBOUND", Timestamp: now},
		{EndpointID: "e1", TenantID: "t-01", DstIP: "10.9.9.8", DstPort: 443, Direction: "OUTBOUND", Timestamp: now},
	}
	if _, err := srv.telemetrySnapshot("t-01", storage.Endpoint{ID: "e1", TenantID: "t-01"}, events); err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	if events[0].Domain != "thumbnails-photos.amazon.com" {
		t.Fatalf("the known address was not named: %q", events[0].Domain)
	}
	if events[1].Domain != "" {
		t.Fatalf("an unknown address was given a name: %q", events[1].Domain)
	}
}

// What the agent itself observed is better evidence than our inference, so a
// domain the agent reported must never be overwritten.
func TestSnapshotDoesNotOverwriteAgentDomain(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()

	if _, _, err := store.RecordDNSResolutions([]storage.DNSResolution{
		{Domain: "inferred.example.com", IP: "10.9.9.9", At: now},
	}, now); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	events := []storage.Event{
		{EndpointID: "e1", TenantID: "t-01", DstIP: "10.9.9.9", DstPort: 443,
			Direction: "OUTBOUND", Domain: "observed.example.com", Timestamp: now},
	}
	if _, err := srv.telemetrySnapshot("t-01", storage.Endpoint{ID: "e1", TenantID: "t-01"}, events); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if events[0].Domain != "observed.example.com" {
		t.Fatalf("the agent's own observation was overwritten: %q", events[0].Domain)
	}
}

// A hub with no resolutions at all must behave exactly as before.
func TestSnapshotWithoutResolutionsIsUnchanged(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	store, err := storage.New(filepath.Join(tmp, "t.db"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	defer store.Close()
	srv := newTestServer(t, store, "mock_admin_token", tmp, "http://127.0.0.1:9999", "1.8.22")

	now := time.Now().UTC()
	events := []storage.Event{
		{EndpointID: "e1", TenantID: "t-01", DstIP: "10.9.9.9", DstPort: 443, Direction: "OUTBOUND", Timestamp: now},
	}
	if _, err := srv.telemetrySnapshot("t-01", storage.Endpoint{ID: "e1", TenantID: "t-01"}, events); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if events[0].Domain != "" {
		t.Fatalf("a name appeared from nowhere: %q", events[0].Domain)
	}
}

// A sample whose byte count is past what a measurement can be (Windows ESTATS
// has returned pointers) keeps its flow and loses its bytes, both of them:
// one bad counter makes the whole sample unmeasured.
func TestNormalizeDropsByteCountsThatAreNotMeasurements(t *testing.T) {
	now := time.Now().UTC()
	in := []storage.Event{
		{DstIP: "10.0.0.2", BytesIn: 8389899496073898413, BytesOut: 64, Timestamp: now},
		{DstIP: "10.0.0.2", BytesIn: 1200, BytesOut: -5, Timestamp: now},
		{DstIP: "10.0.0.2", BytesIn: 1200, BytesOut: 64, Timestamp: now},
	}
	out := normalizeTelemetryEvents(in, "default", "e1", now)
	if len(out) != 3 {
		t.Fatalf("normalize dropped flows: %d of 3", len(out))
	}
	for i, want := range [][2]int64{{0, 0}, {0, 0}, {1200, 64}} {
		if out[i].BytesIn != want[0] || out[i].BytesOut != want[1] {
			t.Errorf("event %d: bytes %d/%d, want %d/%d", i, out[i].BytesIn, out[i].BytesOut, want[0], want[1])
		}
	}
}
