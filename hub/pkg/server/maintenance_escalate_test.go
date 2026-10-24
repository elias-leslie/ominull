package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// A run handed to the owner shows as one decision (group job:<id>, answer
// handled) on the decisions card and in Nightshift's list; answering closes
// it. Unknown jobs and empty reasons are refused.
func TestMaintenanceEscalate(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	authorityOf(t, srv)
	audit := `{"endpoint_ids":["ep-lap"],"packages":["windows-audit"],"mode":"audit"}`
	w := postAdmin(srv, "/api/v1/maintenance/run", audit)
	var run struct {
		Jobs []packageRunJob `json:"jobs"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &run)
	if w.Code != http.StatusCreated || len(run.Jobs) != 1 {
		t.Fatalf("run: %d %s", w.Code, w.Body.String())
	}
	jobID := run.Jobs[0].JobID
	for body, want := range map[string]int{
		`{"job_id":"nope","reason":"x"}`:         http.StatusNotFound,
		`{"job_id":"` + jobID + `","reason":""}`: http.StatusBadRequest,
		`{"job_id":"` + jobID + `"}`:             http.StatusBadRequest,
	} {
		if w := postAdmin(srv, "/api/v1/maintenance/escalate", body); w.Code != want {
			t.Errorf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	if w := postAdmin(srv, "/api/v1/maintenance/escalate", `{"job_id":"`+jobID+`","reason":"the uninstaller wants a password"}`); w.Code != http.StatusOK {
		t.Fatalf("escalate: %d %s", w.Code, w.Body.String())
	}
	v := getDecisions(t, srv)
	var d *ownerDecision
	for i := range v.Open {
		if v.Open[i].Group == "job:"+jobID {
			d = &v.Open[i]
		}
	}
	if d == nil || d.Package != "windows-audit" || len(d.Answers) != 1 || d.Answers[0] != "handled" ||
		!strings.Contains(d.Item.Reason, "the uninstaller wants a password") {
		t.Fatalf("escalated decision: %+v", v.Open)
	}
	if w := postAdmin(srv, "/api/v1/maintenance/decisions", `{"key":"`+d.Key+`","answer":"handled"}`); w.Code != http.StatusOK {
		t.Fatalf("answer: %d %s", w.Code, w.Body.String())
	}
	for _, o := range getDecisions(t, srv).Open {
		if o.Group == "job:"+jobID {
			t.Fatalf("answered escalation still open: %+v", o)
		}
	}
}
