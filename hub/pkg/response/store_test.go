package response

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestStore_JobLifecycleAndTransitions(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	tenantID := "tenant-1"
	endpointID := "ep-1"
	now := time.Now()

	grant := &EndpointGrant{
		Version:           GrantVersion,
		GrantID:           "grant-100",
		TenantID:          tenantID,
		EndpointID:        endpointID,
		ActionKind:        ActionKindForensicCollect,
		ActionDigest:      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		OperatorID:        "op-1",
		ResponseSessionID: "sess-1",
		IssuedAt:          now.Unix(),
		ExpiresAt:         now.Add(1 * time.Hour).Unix(),
		Nonce:             "123456",
		SignerKeyID:       "key-1",
		Signature:         "abcdef",
	}

	payloadJSON := `{"profile":"diagnostic","max_bytes":1048576}`

	// 1. Create Job
	job1, err := store.CreateJob(tenantID, endpointID, ActionKindForensicCollect, "op-1", grant, payloadJSON, "idemp-key-1")
	if err != nil {
		t.Fatalf("CreateJob failed: %v", err)
	}
	if job1.State != StateQueued {
		t.Fatalf("expected queued state, got %s", job1.State)
	}

	// Invalid transition check: Cannot complete a job while queued!
	resEarly := &JobResult{JobID: job1.ID, LeaseID: "none", State: StateSucceeded}
	err = store.CompleteJob(tenantID, endpointID, job1.ID, "none", resEarly)
	if err == nil {
		t.Fatalf("expected CompleteJob to fail for queued job")
	}

	// 2. Offer Pending Jobs
	offers, err := store.OfferPendingJobs(tenantID, endpointID, 4, 1*time.Minute)
	if err != nil {
		t.Fatalf("OfferPendingJobs failed: %v", err)
	}
	if len(offers) != 1 {
		t.Fatalf("expected 1 offer, got %d", len(offers))
	}
	offer := offers[0]
	if offer.JobID != job1.ID || offer.LeaseID == "" {
		t.Fatalf("invalid offer structure: %+v", offer)
	}

	// 3. Tenant and Endpoint Binding checks on ACK
	// Wrong tenant
	err = store.AcknowledgeJob("tenant-other", endpointID, offer.JobID, offer.LeaseID, true, "")
	if err == nil || !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected ErrTenantMismatch on ACK, got %v", err)
	}
	// Wrong endpoint
	err = store.AcknowledgeJob(tenantID, "ep-other", offer.JobID, offer.LeaseID, true, "")
	if err == nil || !errors.Is(err, ErrEndpointMismatch) {
		t.Fatalf("expected ErrEndpointMismatch on ACK, got %v", err)
	}
	// Wrong lease ID
	err = store.AcknowledgeJob(tenantID, endpointID, offer.JobID, "stolen-lease", true, "")
	if err == nil || !errors.Is(err, ErrLeaseMismatch) {
		t.Fatalf("expected ErrLeaseMismatch on ACK, got %v", err)
	}

	// Valid ACK
	if err := store.AcknowledgeJob(tenantID, endpointID, offer.JobID, offer.LeaseID, true, ""); err != nil {
		t.Fatalf("AcknowledgeJob failed: %v", err)
	}

	// 4. Progress Reporting transitions acknowledged -> running
	prog := &JobProgress{
		JobID:       offer.JobID,
		LeaseID:     offer.LeaseID,
		ProgressPct: 50,
		Message:     "collecting memory dump",
	}
	if err := store.RecordProgress(tenantID, endpointID, offer.JobID, offer.LeaseID, prog); err != nil {
		t.Fatalf("RecordProgress failed: %v", err)
	}

	// 5. Tenant and Endpoint Binding on CompleteJob
	result := &JobResult{
		JobID:          offer.JobID,
		LeaseID:        offer.LeaseID,
		State:          StateSucceeded,
		ExitCode:       0,
		DurationMs:     150,
		ManifestSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	// Wrong tenant
	err = store.CompleteJob("tenant-other", endpointID, offer.JobID, offer.LeaseID, result)
	if err == nil || !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected ErrTenantMismatch on CompleteJob, got %v", err)
	}
	// Wrong endpoint
	err = store.CompleteJob(tenantID, "ep-other", offer.JobID, offer.LeaseID, result)
	if err == nil || !errors.Is(err, ErrEndpointMismatch) {
		t.Fatalf("expected ErrEndpointMismatch on CompleteJob, got %v", err)
	}

	// Valid completion
	if err := store.CompleteJob(tenantID, endpointID, offer.JobID, offer.LeaseID, result); err != nil {
		t.Fatalf("CompleteJob failed: %v", err)
	}

	// Replay Protection: idempotent completion
	if err := store.CompleteJob(tenantID, endpointID, offer.JobID, offer.LeaseID, result); err != nil {
		t.Fatalf("expected idempotent success on replayed completion, got: %v", err)
	}

	// 6. Verify Transition Audit Log
	audit, err := store.GetJobAuditLog(tenantID, offer.JobID, 20)
	if err != nil {
		t.Fatalf("GetJobAuditLog failed: %v", err)
	}
	if len(audit) < 4 {
		t.Fatalf("expected at least 4 audit entries (create, offer, ack, progress, complete), got %d", len(audit))
	}

	// 7. Cancellation Lifecycle
	job2, err := store.CreateJob(tenantID, endpointID, ActionKindForensicCollect, "op-1", grant, payloadJSON, "")
	if err != nil {
		t.Fatalf("CreateJob 2 failed: %v", err)
	}
	// Cancelling queued job goes directly to cancelled
	if err := store.CancelJob(tenantID, job2.ID, "op-1"); err != nil {
		t.Fatalf("CancelJob failed: %v", err)
	}
	list, err := store.ListJobs(tenantID, endpointID, 10)
	if err != nil {
		t.Fatalf("ListJobs failed: %v", err)
	}
	var cancelledFound bool
	for _, j := range list {
		if j.ID == job2.ID && j.State == StateCancelled {
			cancelledFound = true
		}
	}
	if !cancelledFound {
		t.Fatalf("expected job2 to be in cancelled state")
	}
}
