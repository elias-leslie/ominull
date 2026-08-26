package detector

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestDetectorEngine(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_detector.db")

	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	eventsChan := make(chan storage.Event, 100)
	var isolatedCount int32

	engine := New(store, eventsChan, func(endpointID, reason string) error {
		atomic.AddInt32(&isolatedCount, 1)
		return nil
	})

	// 1. Test Blocked Threat Auto-Nullification
	engine.Evaluate(storage.Event{
		TenantID:   "default",
		EndpointID: "test-host-01",
		Timestamp:  time.Now().UTC(),
		Action:     "BLOCK",
		Direction:  "OUTBOUND",
		DstIP:      "185.220.101.5",
		DstPort:    443,
	})

	if atomic.LoadInt32(&isolatedCount) != 1 {
		t.Errorf("expected 1 auto-isolation trigger, got %d", isolatedCount)
	}

	// 2. Test Shell Egress Alert
	engine.Evaluate(storage.Event{
		TenantID:    "default",
		EndpointID:  "test-host-02",
		Timestamp:   time.Now().UTC(),
		Action:      "PERMIT",
		Direction:   "OUTBOUND",
		DstIP:       "203.0.113.50",
		DstPort:     4444,
		ProcessPath: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		ProcessID:   1234,
	})

	alerts, err := store.ListAlerts("default", 10)
	if err != nil {
		t.Fatalf("ListAlerts failed: %v", err)
	}
	if len(alerts) != 2 {
		t.Errorf("expected 2 alerts in database, got %d", len(alerts))
	}
}
