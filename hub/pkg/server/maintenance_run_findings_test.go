package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
)

// A run waiting on a window gets its own feed record with the window and the
// next move; once the run ends cleanly the record reads resolved, and a day
// later it drops. A failed run is a medium record.
func TestRunFindings(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	authorityOf(t, srv)
	start := func() (string, string) {
		audit := `{"endpoint_ids":["ep-lap"],"packages":["windows-audit"],"mode":"audit"}`
		w := postAdmin(srv, "/api/v1/maintenance/run", audit)
		var run struct {
			Jobs []packageRunJob `json:"jobs"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &run)
		if w.Code != http.StatusCreated || len(run.Jobs) != 1 {
			t.Fatalf("run: %d %s", w.Code, w.Body.String())
		}
		offers := offerAndAck(t, srv, "ep-lap")
		return run.Jobs[0].JobID, offers[0].LeaseID
	}
	jobID, lease := start()
	if code, _ := heartbeat(t, srv, "ep-lap", `{"job_id":"`+jobID+`","lease_id":"`+lease+`","phase":"needs_hands","idle_seconds":200,
		"window":{"title":"Uninstall Wave Tool","process":"unins000.exe","pid":4242,"session":1}}`); code != http.StatusOK {
		t.Fatalf("needs_hands heartbeat: %d", code)
	}
	uid := runUID("ep-lap", "windows-audit")
	find := func(at time.Time) *feedFinding {
		list, err := srv.runFindings(at)
		if err != nil {
			t.Fatal(err)
		}
		for i := range list {
			if list[i].FindingInfo["uid"] == uid {
				return &list[i]
			}
		}
		return nil
	}
	now := time.Now().UTC()
	f := find(now)
	if f == nil || f.StatusID != ocsfStatusNew || f.SeverityID != ocsfSevLow || f.Unmapped["state"] != "needs_hands" ||
		f.Unmapped["job_id"] != jobID || f.Unmapped["next_move"] != runNextMove("needs_hands", jobID) || f.Unmapped["window"] == nil {
		t.Fatalf("needs_hands record: %+v", f)
	}
	if err := srv.responseStore.CompleteJob("default", "ep-lap", jobID, lease, &response.JobResult{JobID: jobID, LeaseID: lease,
		State: response.StateSucceeded, Stdout: `{"v":1,"state":"ok","reboot":false,"changed":[]}`}); err != nil {
		t.Fatal(err)
	}
	if f := find(now.Add(time.Minute)); f == nil || f.StatusID != ocsfStatusResolved {
		t.Fatalf("after the run ended: %+v", f)
	}
	if f := find(now.Add(25 * time.Hour)); f != nil {
		t.Fatalf("a day later the record should drop: %+v", f)
	}

	jobID, lease = start()
	if err := srv.responseStore.CompleteJob("default", "ep-lap", jobID, lease, &response.JobResult{JobID: jobID, LeaseID: lease,
		State: response.StateFailed, Stdout: "boom"}); err != nil {
		t.Fatal(err)
	}
	if f := find(time.Now().UTC()); f == nil || f.SeverityID != ocsfSevMedium || f.Unmapped["state"] != "failed" {
		t.Fatalf("failed record: %+v", f)
	}
	// A day on, nobody has repeated it: the record closes, but it was not fixed
	// and must not say so.
	aged := time.Now().UTC().Add(25 * time.Hour)
	if f := find(aged); f == nil || f.StatusID != ocsfStatusResolved || f.SeverityID != ocsfSevInformational ||
		!strings.HasPrefix(f.Message, "Over a day old, not repeated yet: windows-audit on laptop-1 failed") {
		t.Fatalf("aged-out record: %+v", f)
	}
	// Once a later run succeeds it is resolved.
	jobID, lease = start()
	if err := srv.responseStore.CompleteJob("default", "ep-lap", jobID, lease, &response.JobResult{JobID: jobID, LeaseID: lease,
		State: response.StateSucceeded, Stdout: `{"v":1,"state":"ok","reboot":false,"changed":[]}`}); err != nil {
		t.Fatal(err)
	}
	if f := find(aged.Add(time.Minute)); f == nil || f.StatusID != ocsfStatusResolved || !strings.HasPrefix(f.Message, "Resolved: windows-audit on laptop-1 failed") {
		t.Fatalf("resolved after a later success: %+v", f)
	}
}

// A failed run on a host that is off now waits on the host: listed, low, not
// critical. Once the host reports again it is critical until repeated.
func TestMaintenanceFailureWaitsOnOfflineHost(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	authorityOf(t, srv)
	w := postAdmin(srv, "/api/v1/maintenance/run", `{"endpoint_ids":["ep-lap"],"packages":["windows-audit"],"mode":"audit"}`)
	var run struct {
		Jobs []packageRunJob `json:"jobs"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &run)
	if w.Code != http.StatusCreated || len(run.Jobs) != 1 {
		t.Fatalf("run: %d %s", w.Code, w.Body.String())
	}
	offers := offerAndAck(t, srv, "ep-lap")
	jobID := run.Jobs[0].JobID
	if err := srv.responseStore.CompleteJob("default", "ep-lap", jobID, offers[0].LeaseID, &response.JobResult{JobID: jobID, LeaseID: offers[0].LeaseID,
		State: response.StateSucceeded, Stdout: `{"v":1,"state":"failed","reboot":false,"changed":[],"detail":{"reason":"Exception from HRESULT: 0x80072EE2"}}`}); err != nil {
		t.Fatal(err)
	}
	ep, err := srv.store.GetEndpoint("ep-lap")
	if err != nil {
		t.Fatal(err)
	}
	record := func(at time.Time) feedFinding {
		fs, err := srv.maintenanceFindings(at)
		if err != nil || len(fs) == 0 {
			t.Fatalf("findings: %v %+v", err, fs)
		}
		return fs[0]
	}
	if f := record(ep.LastSeenAt.Add(time.Minute)); f.SeverityID != ocsfSevCritical || f.Unmapped["waiting"] != nil {
		t.Fatalf("a failure on a host that is online is critical: %+v", f)
	}
	off := ep.LastSeenAt.Add(2 * time.Hour)
	f := record(off)
	want := "windows-audit failed on laptop-1 (Exception from HRESULT: 0x80072EE2); the machine has been off since " +
		ep.LastSeenAt.UTC().Format("2006-01-02 15:04Z") + ", so the run needs repeating when it is back"
	raw, _ := json.Marshal(f.Unmapped["waiting"])
	if f.SeverityID != ocsfSevLow || f.StatusID != ocsfStatusNew || f.Message != want || f.Unmapped["failures"] != nil ||
		!strings.Contains(string(raw), `"package":"windows-audit"`) || !strings.Contains(string(raw), `"reason":"Exception from HRESULT: 0x80072EE2"`) ||
		!strings.Contains(string(raw), `"off_since"`) || len(f.Resources) != 1 || f.Resources[0].UID != "ep-lap" {
		t.Fatalf("a failure on a host that is off should wait on it: %+v %s", f, raw)
	}
	ep.LastSeenAt = off
	if err := srv.store.UpsertEndpoint(*ep); err != nil {
		t.Fatal(err)
	}
	if f := record(off.Add(time.Minute)); f.SeverityID != ocsfSevCritical || f.Unmapped["waiting"] != nil {
		t.Fatalf("back online and not repeated: critical again: %+v", f)
	}
}
