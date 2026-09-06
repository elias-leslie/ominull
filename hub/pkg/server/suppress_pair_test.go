package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func suppressFinding(t *testing.T, srv *Server, id string) (int, map[string]interface{}) {
	t.Helper()
	body := `{"id":"` + id + `"}`
	r := httptest.NewRequest(http.MethodPost, "/api/v1/detection/tuning/suppress", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func seedFinding(t *testing.T, store *storage.Store, id, process, evidence string) {
	t.Helper()
	if err := store.CreateAnomalyAlert(storage.AnomalyAlert{
		ID:          id,
		TenantID:    "default",
		EndpointID:  "ep-1",
		Hostname:    "workstation",
		AnomalyType: "C2_BEACONING",
		Technique:   "T1071.001",
		Severity:    "MEDIUM",
		Title:       "Periodic beaconing",
		Description: "a conversation",
		Evidence:    evidence,
		ProcessPath: process,
		DstIP:       "10.0.0.9",
		DstPort:     443,
		Timestamp:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seeding the finding: %v", err)
	}
}

// The loop the console did not have: say "expected" on a finding, and the rule
// that produced it learns the pair.
func TestMarkingAFindingExpectedWritesThePair(t *testing.T) {
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-1", "/usr/bin/backup-agent", `{"destination_owner":"Acme Vendor","destination_tenancy":"vendor"}`)

	code, body := suppressFinding(t, srv, "f-1")
	if code != http.StatusOK {
		t.Fatalf("suppress: %d %v", code, body)
	}
	if body["pair"] != "backup-agent@acme vendor" {
		t.Fatalf("silenced the wrong thing: %v", body["pair"])
	}

	tuning := store.GetDetectionTuning()
	if !tuning.IsVouchedPair("backup-agent", "Acme Vendor", "vendor") {
		t.Fatal("the pair was not written into the tuning, so the same finding raises again tomorrow")
	}
	// Silencing one program talking to that owner must not silence every
	// program talking to it.
	if tuning.IsVouchedPair("curl", "Acme Vendor", "vendor") {
		t.Fatal("the whole owner was silenced, not the pair")
	}

	found, err := store.GetAnomalyAlert("f-1")
	if err != nil {
		t.Fatalf("reading the finding back: %v", err)
	}
	if !found.Acknowledged {
		t.Error("the finding that was just explained is still sitting in the open list")
	}
}

// Rented compute is where an implant hides behind a reputable-sounding name.
// It is barred in the tuning, and it has to be barred at the door as well, or
// the button becomes the way to write the entry the tuning refuses.
func TestRentedComputeCannotBeMarkedExpected(t *testing.T) {
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-2", "/usr/bin/python3.13", `{"destination_owner":"Some Cloud (customer)","destination_tenancy":"hosting"}`)

	code, body := suppressFinding(t, srv, "f-2")
	if code != http.StatusBadRequest {
		t.Fatalf("rented compute was accepted: %d %v", code, body)
	}
	if len(store.GetDetectionTuning().QuietPairs) != 0 {
		t.Fatal("a pair was written for a destination on rented compute")
	}
	found, _ := store.GetAnomalyAlert("f-2")
	if found.Acknowledged {
		t.Error("a refused suppression still cleared the finding")
	}
}

// "unknown" is what an agent sends when nothing owns the socket. There is no
// program there to vouch for.
func TestAnUnattributedProcessCannotBeMarkedExpected(t *testing.T) {
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-3", "unknown", `{"destination_owner":"Acme Vendor","destination_tenancy":"vendor"}`)

	code, _ := suppressFinding(t, srv, "f-3")
	if code != http.StatusBadRequest {
		t.Fatalf("an unattributed process was vouched for: %d", code)
	}
	if len(store.GetDetectionTuning().QuietPairs) != 0 {
		t.Fatal("a pair was written with no program on one side of it")
	}
}

// An address nobody can name is not a counterparty, and silencing one would
// silence whatever answers on it next.
func TestAnUnnamedNetworkCannotBeMarkedExpected(t *testing.T) {
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-4", "/usr/bin/curl", `{"attribution_status":"authoritative"}`)

	code, _ := suppressFinding(t, srv, "f-4")
	if code != http.StatusBadRequest {
		t.Fatalf("an unnamed network was silenced: %d", code)
	}
}

// Loosening a detector is an administrator's decision, like every other write
// to the tuning.
func TestMarkingExpectedIsAnAdministratorAction(t *testing.T) {
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-5", "/usr/bin/backup-agent", `{"destination_owner":"Acme Vendor","destination_tenancy":"vendor"}`)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/detection/tuning/suppress", strings.NewReader(`{"id":"f-5"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-API-Key", "mock_tenant_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusOK {
		t.Fatalf("a tenant credential silenced a detector: %d", w.Code)
	}
	if len(store.GetDetectionTuning().QuietPairs) != 0 {
		t.Fatal("a pair was written without administrator authority")
	}
}

// Pressing it twice is not an error, and does not write the pair twice.
func TestMarkingExpectedTwiceIsIdempotent(t *testing.T) {
	srv, store := setupTestServer(t)
	seedFinding(t, store, "f-6", "/usr/bin/backup-agent", `{"destination_owner":"Acme Vendor","destination_tenancy":"vendor"}`)
	seedFinding(t, store, "f-7", "/usr/bin/backup-agent", `{"destination_owner":"Acme Vendor","destination_tenancy":"vendor"}`)

	if code, _ := suppressFinding(t, srv, "f-6"); code != http.StatusOK {
		t.Fatalf("first suppression: %d", code)
	}
	code, body := suppressFinding(t, srv, "f-7")
	if code != http.StatusOK {
		t.Fatalf("second suppression: %d %v", code, body)
	}
	if body["added"] != false {
		t.Error("the second press claimed to have added the pair again")
	}
	count := 0
	for _, p := range store.GetDetectionTuning().QuietPairs {
		if strings.EqualFold(p, "backup-agent@acme vendor") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("the pair is in the tuning %d times", count)
	}
	found, _ := store.GetAnomalyAlert("f-7")
	if !found.Acknowledged {
		t.Error("the second finding was left open")
	}
}
