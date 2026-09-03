package response

import (
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestStore_JobLifecycle(t *testing.T) {
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

	// 1. Create Job with Idempotency Key
	job1, err := store.CreateJob(tenantID, endpointID, ActionKindForensicCollect, "op-1", grant, payloadJSON, "idemp-key-1")
	if err != nil {
		t.Fatalf("CreateJob failed: %v", err)
	}
	if job1.State != StateQueued {
		t.Fatalf("expected queued state, got %s", job1.State)
	}

	// Re-submitting same idempotency key returns existing job
	jobDup, err := store.CreateJob(tenantID, endpointID, ActionKindForensicCollect, "op-1", grant, payloadJSON, "idemp-key-1")
	if err != nil {
		t.Fatalf("CreateJob dup failed: %v", err)
	}
	if jobDup.ID != job1.ID {
		t.Fatalf("expected same job ID for idempotency key, got %s vs %s", jobDup.ID, job1.ID)
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

	// 3. Acknowledge Job
	if err := store.AcknowledgeJob(offer.JobID, offer.LeaseID, true, ""); err != nil {
		t.Fatalf("AcknowledgeJob failed: %v", err)
	}

	// 4. Complete Job
	result := &JobResult{
		JobID:          offer.JobID,
		LeaseID:        offer.LeaseID,
		State:          StateSucceeded,
		ExitCode:       0,
		DurationMs:     150,
		ManifestSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	if err := store.CompleteJob(offer.JobID, offer.LeaseID, result); err != nil {
		t.Fatalf("CompleteJob failed: %v", err)
	}

	// 5. List Jobs
	list, err := store.ListJobs(tenantID, endpointID, 10)
	if err != nil {
		t.Fatalf("ListJobs failed: %v", err)
	}
	if len(list) != 1 || list[0].State != StateSucceeded {
		t.Fatalf("expected 1 succeeded job in list, got: %+v", list)
	}

	// 6. Test Cancel on new job
	grant2 := *grant
	grant2.GrantID = "grant-200"
	job2, err := store.CreateJob(tenantID, endpointID, ActionKindScriptExec, "op-1", &grant2, `{"source":"echo hi"}`, "")
	if err != nil {
		t.Fatalf("CreateJob 2 failed: %v", err)
	}
	if err := store.CancelJob(job2.ID, "op-1"); err != nil {
		t.Fatalf("CancelJob failed: %v", err)
	}

	list2, err := store.ListJobs(tenantID, endpointID, 10)
	if err != nil {
		t.Fatalf("ListJobs failed: %v", err)
	}
	if len(list2) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(list2))
	}
}
