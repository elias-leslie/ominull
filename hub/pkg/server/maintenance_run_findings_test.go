package server

import (
	"encoding/json"
	"net/http"
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
}
