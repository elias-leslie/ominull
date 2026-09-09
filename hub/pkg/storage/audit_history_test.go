package storage

import (
	"testing"
	"time"
)

func TestAuditHistoryStableAcrossConcurrentAndBackdatedInserts(t *testing.T) {
	s := newTestStore(t)
	at := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	put := func(id, tenant string, when time.Time) {
		t.Helper()
		if err := s.RecordAudit(AuditEntry{ID: id, TenantID: tenant, Username: "fixture", Action: "READ", Timestamp: when}); err != nil {
			t.Fatal(err)
		}
	}
	put("a", "one", at)
	put("b", "one", at)
	put("z", "two", at.Add(time.Hour))
	filter := AuditFilter{Actor: "fixture", Action: "READ", From: at.Add(-time.Hour), To: at.Add(time.Hour)}
	page, err := s.AuditHistory("one", 1, "", filter)
	if err != nil || len(page.Entries) != 1 || page.Entries[0].ID != "b" || page.Next == "" {
		t.Fatalf("first page: %+v %v", page, err)
	}
	put("new", "one", at.Add(time.Minute))
	put("backdated", "one", at.Add(-time.Minute))
	next, err := s.AuditHistory("one", 1, page.Next, filter)
	if err != nil || len(next.Entries) != 1 || next.Entries[0].ID != "a" || next.Next != "" {
		t.Fatalf("shifted history: %+v %v", next, err)
	}
	empty, err := s.AuditHistory("one", 100, "", AuditFilter{Actor: "someone-else"})
	if err != nil || len(empty.Entries) != 0 {
		t.Fatal(empty, err)
	}
	if _, err := s.AuditHistory("one", 100, "not a cursor", filter); err == nil {
		t.Fatal("invalid cursor accepted")
	}
}
