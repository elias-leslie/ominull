package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestTrafficOverviewAndFlows(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "traffic_test.db")
	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("storage.New() failed: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	// Insert batch of test events
	events := []Event{
		{
			Timestamp:   now.Add(-10 * time.Minute),
			EndpointID:  "ep-01",
			Layer:       "c-agent-raw",
			Action:      "PERMIT",
			Direction:   "OUTBOUND",
			Protocol:    6,
			SrcIP:       "10.0.0.10",
			DstIP:       "142.250.190.46",
			SrcPort:     49152,
			DstPort:     443,
			ProcessPath: "/usr/bin/curl",
			Domain:      "google.com",
			Country:     "US",
			BytesIn:     4500,
			BytesOut:    1200,
		},
		{
			Timestamp:   now.Add(-5 * time.Minute),
			EndpointID:  "ep-01",
			Layer:       "c-agent-raw",
			Action:      "BLOCK",
			Direction:   "OUTBOUND",
			Protocol:    6,
			SrcIP:       "10.0.0.10",
			DstIP:       "198.51.100.1",
			SrcPort:     49153,
			DstPort:     80,
			ProcessPath: "/usr/bin/malware",
			Domain:      "evil.com",
			Country:     "RU",
			BytesIn:     0,
			BytesOut:    0,
		},
		{
			Timestamp:   now.Add(-2 * time.Minute),
			EndpointID:  "ep-02",
			Layer:       "c-agent-raw",
			Action:      "PERMIT",
			Direction:   "INBOUND",
			Protocol:    17,
			SrcIP:       "10.0.0.1",
			DstIP:       "10.0.0.20",
			SrcPort:     53,
			DstPort:     53535,
			ProcessPath: "/usr/sbin/systemd-resolved",
			Domain:      "",
			Country:     "US",
			BytesIn:     256,
			BytesOut:    80,
		},
	}

	if err := store.InsertEventsBatch(events); err != nil {
		t.Fatalf("InsertEventsBatch failed: %v", err)
	}

	// 1. Query Overview
	overview, err := store.QueryTrafficOverview(TrafficFilter{
		TenantID: "default",
		Range:    "1h",
	})
	if err != nil {
		t.Fatalf("QueryTrafficOverview failed: %v", err)
	}

	if overview.TotalFlows != 3 {
		t.Errorf("expected 3 total flows, got %d", overview.TotalFlows)
	}
	if overview.MeasuredFlows != 2 {
		t.Errorf("expected 2 measured flows, got %d", overview.MeasuredFlows)
	}
	if overview.Totals.BlockCount != 1 {
		t.Errorf("expected 1 block count, got %d", overview.Totals.BlockCount)
	}
	if overview.Totals.TotalBytes != (4500 + 1200 + 256 + 80) {
		t.Errorf("expected total bytes %d, got %d", (4500 + 1200 + 256 + 80), overview.Totals.TotalBytes)
	}
	if len(overview.Trends) == 0 {
		t.Errorf("expected trend buckets, got 0")
	}

	// 2. Query Flows
	flowsRes, err := store.QueryTrafficFlows(TrafficFilter{
		TenantID: "default",
		Range:    "1h",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("QueryTrafficFlows failed: %v", err)
	}
	if flowsRes.Total != 3 {
		t.Errorf("expected 3 flows total, got %d", flowsRes.Total)
	}
	if len(flowsRes.Flows) != 3 {
		t.Fatalf("expected 3 flows in page, got %d", len(flowsRes.Flows))
	}

	// 3. Query Single Flow by ID
	firstFlowID := flowsRes.Flows[0].ID
	singleFlow, err := store.GetTrafficFlowByID(firstFlowID, "default")
	if err != nil {
		t.Fatalf("GetTrafficFlowByID failed: %v", err)
	}
	if singleFlow == nil || singleFlow.ID != firstFlowID {
		t.Errorf("unexpected single flow: %+v", singleFlow)
	}
}

// The trend lanes are built by laying out one slot per bucket and filing each
// grouped row into the slot its timestamp falls in. That indexing was done
// through pointers taken into a slice that was still being appended to, so every
// pointer handed out before the last reallocation addressed an abandoned array
// and the rows filed through it were dropped: on a one-hour window at
// one-minute buckets only the last twenty-six of sixty-one slots could receive
// anything, and the console drew an empty first half with every bar packed to
// the right. The existing coverage never saw it because its three events all sat
// in the final ten minutes.
//
// This test spreads one event across every minute of the window, so a slot that
// cannot be written to is a slot that reads zero.
func TestTrendBucketsCoverTheWholeWindow(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "trend_window.db"))
	if err != nil {
		t.Fatalf("storage.New() failed: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	var events []Event
	const minutes = 55
	for i := 1; i <= minutes; i++ {
		events = append(events, Event{
			Timestamp:   now.Add(-time.Duration(i) * time.Minute),
			EndpointID:  "ep-01",
			Layer:       "c-agent-raw",
			Action:      "PERMIT",
			Direction:   "OUTBOUND",
			Protocol:    6,
			SrcIP:       "10.0.0.10",
			DstIP:       "10.0.0.20",
			SrcPort:     49152,
			DstPort:     443,
			ProcessPath: "/usr/bin/curl",
			Country:     "US",
			BytesIn:     int64(100 * i),
			BytesOut:    int64(10 * i),
		})
	}
	if err := store.InsertEventsBatch(events); err != nil {
		t.Fatalf("InsertEventsBatch failed: %v", err)
	}

	overview, err := store.QueryTrafficOverview(TrafficFilter{TenantID: "default", Range: "1h"})
	if err != nil {
		t.Fatalf("QueryTrafficOverview failed: %v", err)
	}
	if overview.TotalFlows != int64(minutes) {
		t.Fatalf("expected %d flows in the window, got %d", minutes, overview.TotalFlows)
	}

	// Every flow the totals counted has to appear in a bucket. A bucket sum
	// short of the total is the defect this test exists for, whatever the cause.
	var bucketFlows, bucketBytes int64
	firstNonEmpty := -1
	for i, bucket := range overview.Trends {
		bucketFlows += bucket.Flows
		bucketBytes += bucket.BytesIn + bucket.BytesOut
		if bucket.Flows > 0 && firstNonEmpty < 0 {
			firstNonEmpty = i
		}
	}
	if bucketFlows != overview.Totals.FlowCount {
		t.Errorf("trend buckets hold %d flows but the window totals %d; buckets are dropping rows",
			bucketFlows, overview.Totals.FlowCount)
	}
	if bucketBytes != overview.Totals.TotalBytes {
		t.Errorf("trend buckets hold %d bytes but the window totals %d", bucketBytes, overview.Totals.TotalBytes)
	}
	// The oldest event is 55 minutes back in a 60 minute window, so the series
	// has to start in its first quarter. Right-packing put it past the middle.
	if firstNonEmpty < 0 || firstNonEmpty > len(overview.Trends)/4 {
		t.Errorf("first populated bucket is %d of %d; the series is packed to the right of the window",
			firstNonEmpty, len(overview.Trends))
	}
	// A bucket must be stamped with a boundary it could actually contain rows
	// for, because the axis label under the bar claims that is what it covers.
	step := time.Minute
	for _, bucket := range overview.Trends {
		if !bucket.Timestamp.Truncate(step).Equal(bucket.Timestamp) {
			t.Fatalf("bucket %s is not aligned to its %s boundary", bucket.Timestamp, step)
		}
	}
}

// The console cannot tell a quiet estate from a hub that only has the last few
// minutes unless the payload says how far back the data goes.
func TestOverviewReportsHowFarBackTelemetryGoes(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "trend_retention.db"))
	if err != nil {
		t.Fatalf("storage.New() failed: %v", err)
	}
	defer store.Close()

	empty, err := store.QueryTrafficOverview(TrafficFilter{TenantID: "default", Range: "1h"})
	if err != nil {
		t.Fatalf("QueryTrafficOverview failed: %v", err)
	}
	if empty.RetainedFrom != nil {
		t.Errorf("a hub holding no telemetry must report no retention floor, got %s", empty.RetainedFrom)
	}

	oldest := time.Now().UTC().Add(-9 * time.Minute)
	if err := store.InsertEventsBatch([]Event{{
		Timestamp: oldest, EndpointID: "ep-01", Layer: "c-agent-raw", Action: "PERMIT",
		Direction: "OUTBOUND", Protocol: 6, SrcIP: "10.0.0.10", DstIP: "10.0.0.20",
		SrcPort: 49152, DstPort: 443, ProcessPath: "/usr/bin/curl", Country: "US",
		BytesIn: 10, BytesOut: 20,
	}}); err != nil {
		t.Fatalf("InsertEventsBatch failed: %v", err)
	}

	// A distinct filter, because the previous answer is cached for 15 seconds.
	overview, err := store.QueryTrafficOverview(TrafficFilter{TenantID: "default", Range: "1h", EndpointID: "ep-01"})
	if err != nil {
		t.Fatalf("QueryTrafficOverview failed: %v", err)
	}
	if overview.RetainedFrom == nil {
		t.Fatalf("expected a retention floor once the hub holds telemetry")
	}
	if drift := overview.RetainedFrom.Sub(oldest); drift > time.Second || drift < -time.Second {
		t.Errorf("retention floor %s does not match the oldest event %s", overview.RetainedFrom, oldest)
	}
	if !overview.RetainedFrom.After(overview.WindowStart) {
		t.Errorf("a floor inside the window must read as later than the window start; floor %s, window from %s",
			overview.RetainedFrom, overview.WindowStart)
	}
}
