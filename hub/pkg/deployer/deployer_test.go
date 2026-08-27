package deployer

import (
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestDeployerQueueAndStatus(t *testing.T) {
	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatalf("failed to init storage: %v", err)
	}
	defer store.Close()

	d := New(store, "http://localhost:9999", "test-admin-key")

	req := DeployRequest{
		TargetIP:   "10.0.0.199",
		Port:       2222,
		Username:   "testuser",
		Password:   "testpass",
		OS:         "linux",
		Role:       "workstation",
		LocationID: "loc-home",
		TenantID:   "default",
	}

	jobID, err := d.DispatchPush(req)
	if err != nil {
		t.Fatalf("DispatchPush failed: %v", err)
	}

	if jobID == "" {
		t.Fatalf("Expected non-empty jobID")
	}

	// Poll job status
	time.Sleep(100 * time.Millisecond)
	st, err := d.GetJobStatus(jobID)
	if err != nil {
		t.Fatalf("GetJobStatus failed: %v", err)
	}

	if st.TargetIP != "10.0.0.199" {
		t.Errorf("Expected TargetIP 10.0.0.199, got: %s", st.TargetIP)
	}

	jobs := d.ListJobs()
	if len(jobs) != 1 {
		t.Errorf("Expected 1 job in ListJobs, got: %d", len(jobs))
	}
}
