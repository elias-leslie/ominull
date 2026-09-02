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

	// 1. Save and List Rules
	rule1 := DNSRule{
		Domain:  "malicious.example.com",
		Action:  "BLOCK",
		Source:  "local",
		Comment: "Test block",
	}
	if err := store.SaveDNSRule(&rule1); err != nil {
		t.Fatalf("SaveDNSRule(rule1) failed: %v", err)
	}

	rule2 := DNSRule{
		Domain:  "safe.example.com",
		Action:  "ALLOW",
		Source:  "local",
		Comment: "Test allow",
	}
	if err := store.SaveDNSRule(&rule2); err != nil {
		t.Fatalf("SaveDNSRule(rule2) failed: %v", err)
	}

	rules, err := store.ListDNSRules("default")
	if err != nil {
		t.Fatalf("ListDNSRules failed: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

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

	// 3. Delete Rule
	if err := store.DeleteDNSRule(rule1.ID, "default"); err != nil {
		t.Fatalf("DeleteDNSRule failed: %v", err)
	}
	rulesAfter, err := store.ListDNSRules("default")
	if err != nil {
		t.Fatalf("ListDNSRules after delete failed: %v", err)
	}
	if len(rulesAfter) != 1 {
		t.Fatalf("expected 1 rule after delete, got %d", len(rulesAfter))
	}
}
