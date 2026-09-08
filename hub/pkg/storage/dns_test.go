package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDNSStorage(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_dns.db")

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer store.Close()

	// 2. Record and List Events
	now := time.Now().UTC()
	ev := DNSEvent{
		Timestamp:    now,
		ClientIP:     "10.0.0.100",
		Domain:       "malicious.example.com",
		QType:        "A",
		Action:       "BLOCK",
		Status:       "BLOCKED",
		ResponseCode: "NOERROR",
		LatencyUs:    150,
		Transport:    "udp",
		BlockReason:  "Local blocklist match",
	}
	if err := store.RecordDNSEvent(ev); err != nil {
		t.Fatalf("RecordDNSEvent failed: %v", err)
	}

	events, total, err := store.ListDNSEvents("default", DNSEventFilter{})
	if err != nil {
		t.Fatalf("ListDNSEvents failed: %v", err)
	}
	if total != 1 || len(events) != 1 {
		t.Fatalf("expected 1 event, got total=%d len=%d", total, len(events))
	}
	if events[0].Domain != "malicious.example.com" || events[0].Action != "BLOCK" {
		t.Errorf("unexpected event: %+v", events[0])
	}

}
