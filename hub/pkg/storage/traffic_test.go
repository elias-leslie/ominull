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
			SrcIP:       "192.168.86.10",
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
			SrcIP:       "192.168.86.10",
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
			DstIP:       "192.168.86.20",
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
