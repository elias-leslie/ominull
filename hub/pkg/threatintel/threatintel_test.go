package threatintel

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestThreatIntelManager(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_ti.db")

	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	mgr := New(store)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := mgr.SyncAllFeeds(ctx); err != nil {
		t.Fatalf("SyncAllFeeds failed: %v", err)
	}

	// Verify indicators loaded into fast lookup cache
	iocs, err := store.ListIOCs(100)
	if err != nil {
		t.Fatalf("ListIOCs failed: %v", err)
	}
	if len(iocs) == 0 {
		t.Fatalf("expected active IOCs to be loaded into database")
	}

	// Verify threat lookup against a known indicator from the list
	testIOC := iocs[0]
	matchedIOC, found := mgr.CheckThreat(testIOC.Value)
	if !found {
		t.Fatalf("expected %s to be found in TI cache", testIOC.Value)
	}
	if matchedIOC.Value != testIOC.Value {
		t.Errorf("matched IOC value mismatch: got %s, want %s", matchedIOC.Value, testIOC.Value)
	}

	// Verify clean IP is not flagged
	_, foundClean := mgr.CheckThreat("8.8.8.8")
	if foundClean {
		t.Fatalf("8.8.8.8 should not be in threat feed")
	}
}
