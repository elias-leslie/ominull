package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStorageLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_ominull.db")

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	// 1. Tenant Creation & Lookup
	tenant := Tenant{
		ID:        "tenant-mssp-01",
		Name:      "Acme Cyber Defense",
		APIKey:    "dummy_mock_key_01",
		CreatedAt: time.Now().UTC(),
	}

	if err := store.CreateTenant(tenant); err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	found, err := store.GetTenantByAPIKey("dummy_mock_key_01")
	if err != nil || found == nil {
		t.Fatalf("GetTenantByAPIKey failed: %v", err)
	}
	if found.Name != "Acme Cyber Defense" {
		t.Errorf("Expected tenant name 'Acme Cyber Defense', got '%s'", found.Name)
	}

	// 2. Endpoint Registration
	ep := Endpoint{
		ID:            "ep-win11-01",
		TenantID:      tenant.ID,
		Hostname:      "DESKTOP-IR01",
		OS:            "Windows 11 Enterprise",
		IP:            "10.0.0.110",
		DriverVersion: "1.0.0",
		Status:        "online",
		IsIsolated:    false,
		LastSeenAt:    time.Now().UTC(),
		CreatedAt:     time.Now().UTC(),
	}

	if err := store.UpsertEndpoint(ep); err != nil {
		t.Fatalf("UpsertEndpoint failed: %v", err)
	}

	endpoints, err := store.ListEndpoints(tenant.ID)
	if err != nil || len(endpoints) != 1 {
		t.Fatalf("ListEndpoints failed: len=%d, err=%v", len(endpoints), err)
	}

	// 3. Events Ingestion & Query
	events := []Event{
		{
			TenantID:    tenant.ID,
			EndpointID:  ep.ID,
			Timestamp:   time.Now().UTC(),
			Layer:       "CONNECT_V4",
			Action:      "PERMIT",
			Direction:   "OUTBOUND",
			Protocol:    6,
			SrcIP:       "10.0.0.110",
			DstIP:       "1.1.1.1",
			SrcPort:     49152,
			DstPort:     443,
			ProcessPath: "C:\\Windows\\System32\\svchost.exe",
			ProcessID:   1120,
		},
		{
			TenantID:    tenant.ID,
			EndpointID:  ep.ID,
			Timestamp:   time.Now().UTC(),
			Layer:       "CONNECT_V4",
			Action:      "BLOCK",
			Direction:   "OUTBOUND",
			Protocol:    6,
			SrcIP:       "10.0.0.110",
			DstIP:       "198.51.100.25",
			SrcPort:     49153,
			DstPort:     8080,
			ProcessPath: "C:\\Users\\Analyst\\AppData\\Local\\Temp\\malware.exe",
			ProcessID:   4488,
		},
	}

	if err := store.InsertEventsBatch(events); err != nil {
		t.Fatalf("InsertEventsBatch failed: %v", err)
	}

	queried, err := store.QueryEvents(tenant.ID, ep.ID, 10)
	if err != nil || len(queried) != 2 {
		t.Fatalf("QueryEvents failed: len=%d, err=%v", len(queried), err)
	}

	if queried[0].Action != "BLOCK" && queried[1].Action != "BLOCK" {
		t.Errorf("Expected blocked event in query results")
	}

	// 4. Host Isolation State Toggle
	if err := store.SetEndpointIsolation(ep.ID, true, nil); err != nil {
		t.Fatalf("SetEndpointIsolation failed: %v", err)
	}

	endpoints, _ = store.ListEndpoints(tenant.ID)
	if !endpoints[0].IsIsolated {
		t.Errorf("Expected endpoint to be isolated")
	}
}

func init() {
	// Suppress unneeded warnings
	os.Setenv("SQLITE_TMPDIR", os.TempDir())
}

// The bandwidth timeline used to be the all-time totals divided by six with a
// fixed slope added, which drew a tidy declining trend no traffic had produced
// and blocked-flow bars above a "0 blocked" figure taken from the same
// response. These are the properties that make it a measurement: the bytes are
// the bytes that were reported, a quiet bucket reads zero rather than borrowing
// from a busy one, and traffic older than the window is not folded in.
func TestBandwidthTimelineMeasuresTrafficRatherThanInventingIt(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "timeline.db"))
	if err != nil {
		t.Fatalf("storage init failed: %v", err)
	}
	defer store.Close()

	if err := store.CreateTenant(Tenant{ID: "t-tl", Name: "Timeline", APIKey: "k-tl", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}
	if err := store.UpsertEndpoint(Endpoint{ID: "ep-tl", TenantID: "t-tl", Hostname: "h", OS: "Linux"}); err != nil {
		t.Fatalf("UpsertEndpoint failed: %v", err)
	}

	now := time.Now().UTC()
	ev := func(at time.Time, action string, in, out int64) Event {
		return Event{
			TenantID: "t-tl", EndpointID: "ep-tl", Timestamp: at, Layer: "linux-socket-v1", Action: action,
			Direction: "OUTBOUND", Protocol: 6, SrcIP: "10.0.0.2", DstIP: "10.0.0.3",
			SrcPort: 1, DstPort: 443, BytesIn: in, BytesOut: out, Country: "US", ProcessPath: "p",
		}
	}
	// Two flows five minutes ago, one of them blocked, and one flow well
	// outside the window that must not appear anywhere in the series.
	for _, e := range []Event{
		ev(now.Add(-5*time.Minute), "PERMIT", 1000, 500),
		ev(now.Add(-5*time.Minute), "BLOCK", 200, 0),
		ev(now.Add(-6*time.Hour), "PERMIT", 999999, 999999),
	} {
		if err := store.InsertEvent(e); err != nil {
			t.Fatalf("InsertEvent failed: %v", err)
		}
	}

	sum, err := store.GetAnalyticsSummary("t-tl")
	if err != nil {
		t.Fatalf("GetAnalyticsSummary failed: %v", err)
	}
	if len(sum.BandwidthTimeline) != 6 {
		t.Fatalf("timeline has %d buckets, want 6", len(sum.BandwidthTimeline))
	}

	var in, out, blocks int64
	quiet := 0
	for _, p := range sum.BandwidthTimeline {
		in += p.BytesIn
		out += p.BytesOut
		blocks += p.Blocks
		if p.BytesIn == 0 && p.BytesOut == 0 && p.Blocks == 0 {
			quiet++
		}
	}
	if in != 1200 || out != 500 {
		t.Errorf("timeline totals are %d in / %d out; the window holds 1200 in / 500 out", in, out)
	}
	if blocks != 1 {
		t.Errorf("timeline reports %d blocked flows; one flow in the window was blocked", blocks)
	}
	if quiet == 0 {
		t.Errorf("every bucket carries traffic, but only one ten-minute window had any: %+v", sum.BandwidthTimeline)
	}

	// The chart sits directly under a "blocked" figure from the same response.
	// The two disagreeing is what made the old series obviously invented.
	if sum.TotalBlocks < blocks {
		t.Errorf("the timeline shows %d blocked flows and the summary %d; the chart contradicts the figure above it", blocks, sum.TotalBlocks)
	}
}
