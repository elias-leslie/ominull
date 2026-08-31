package storage

import (
	"path/filepath"
	"testing"
	"time"
)

// TestInsertEventsBatchPropagatesStatementFailure is the red-capable
// correctness seam for batch ingestion. A failed statement must abort the
// transaction; acknowledging a partial batch loses accepted telemetry.
func TestInsertEventsBatchPropagatesStatementFailure(t *testing.T) {
	store, err := New(filepath.Join(t.TempDir(), "batch-failure.db"))
	if err != nil {
		t.Fatalf("storage init failed: %v", err)
	}
	defer store.Close()

	if err := store.UpsertEndpoint(Endpoint{
		ID: "batch-failure-endpoint", TenantID: "default", Hostname: "batch-failure",
		OS: "Linux", IP: "10.0.4.30", DriverVersion: "test", Status: "online",
	}); err != nil {
		t.Fatalf("endpoint setup failed: %v", err)
	}
	if _, err := store.db.Exec(`
		CREATE TRIGGER reject_batch_failure_event
		BEFORE INSERT ON events
		WHEN NEW.dst_ip = '198.51.100.254'
		BEGIN
			SELECT RAISE(ABORT, 'rejected test event');
		END`); err != nil {
		t.Fatalf("trigger setup failed: %v", err)
	}

	base := Event{
		TenantID: "default", EndpointID: "batch-failure-endpoint", Timestamp: time.Now().UTC(),
		Layer: "linux-socket-v1", Action: "PERMIT", Direction: "OUTBOUND", Protocol: 6,
		SrcIP: "10.0.4.30", DstIP: "203.0.113.10", SrcPort: 4000, DstPort: 443,
		ProcessPath: "/usr/sbin/test-agent", ProcessID: 1,
	}
	failed := base
	failed.DstIP = "198.51.100.254"

	err = store.InsertEventsBatch([]Event{base, failed})
	if err == nil {
		t.Fatal("InsertEventsBatch returned nil after a statement failure")
	}

	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM events WHERE endpoint_id = ?", base.EndpointID).Scan(&count); err != nil {
		t.Fatalf("counting rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("failed batch left %d durable rows", count)
	}
	t.Logf("statement failure propagated: %v", err)
}
