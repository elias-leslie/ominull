package server

import (
	"testing"
	"time"
)

func TestEvidenceRetentionPrunesExpiredBundlesWithoutAnOperatorCall(t *testing.T) {
	t.Parallel()
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()
	if srv.evidenceStore == nil {
		t.Fatal("test server has no evidence store")
	}
	expired, err := srv.evidenceStore.CreateBundle("default", "ep-1", "term-old", "terminal_session", -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	live, err := srv.evidenceStore.CreateBundle("default", "ep-1", "term-new", "terminal_session", 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	defer close(stop)
	srv.startEvidenceRetention(time.Hour, stop)

	if _, err := srv.evidenceStore.GetBundle("default", expired.ID); err == nil {
		t.Fatal("expired terminal recording bundle survived the retention prune")
	}
	if _, err := srv.evidenceStore.GetBundle("default", live.ID); err != nil {
		t.Fatalf("unexpired bundle was pruned: %v", err)
	}
}
