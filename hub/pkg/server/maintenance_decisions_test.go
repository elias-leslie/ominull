package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/scripts"
	"ominull/hub/pkg/storage"
)

// runRemoval runs a software removal audit on ep-lap under the owner's tap and
// finishes it with stdout.
func runRemoval(t *testing.T, srv *Server, stdout string) {
	t.Helper()
	audit := `{"endpoint_ids":["ep-lap"],"packages":["windows-software-removal"],"mode":"audit"}`
	id := pendingID(t, adminPost(srv, "/api/v1/maintenance/run", audit, ""))
	ownerOf(t, srv).approve(t, id)
	if w := adminPost(srv, "/api/v1/maintenance/run", audit, id); w.Code != http.StatusCreated {
		t.Fatalf("approved audit: %d %s", w.Code, w.Body.String())
	}
	offers, err := srv.responseStore.OfferPendingJobs("default", "ep-lap", 4, time.Minute)
	if err != nil || len(offers) != 1 {
		t.Fatalf("offers: %v %d", err, len(offers))
	}
	o := offers[0]
	_ = srv.responseStore.AcknowledgeJob("default", "ep-lap", o.JobID, o.LeaseID, true, "")
	if err := srv.responseStore.CompleteJob("default", "ep-lap", o.JobID, o.LeaseID, &response.JobResult{JobID: o.JobID, LeaseID: o.LeaseID,
		State: response.StateSucceeded, Stdout: stdout}); err != nil {
		t.Fatal(err)
	}
}

type decisionsView struct {
	Open     []ownerDecision `json:"open"`
	Answered []ownerDecision `json:"answered"`
}

func getDecisions(t *testing.T, srv *Server) decisionsView {
	t.Helper()
	var v decisionsView
	w := adminDo(srv, http.MethodGet, "/api/v1/maintenance/decisions", "")
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &v) != nil {
		t.Fatalf("decisions: %d %s", w.Code, w.Body.String())
	}
	return v
}

// What a run leaves for the owner rolls up into one feed record for the run;
// keep becomes the machine's override with the owner's reason, handled just
// closes it, and an answered item comes back only if a later run reports it.
func TestOwnerDecisions(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.responseEnabled = true
	ownerOf(t, srv)
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-lap", TenantID: "default", Hostname: "laptop-1", OS: "Windows 11 Home", Status: "online", LastSeenAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	syncRealPackage(t, srv, "software-removal.ps1")
	result := `{"v":1,"state":"drift","reboot":false,"changed":[],"detail":{"needs_owner":[` +
		`{"id":"wave-tool","name":"Wave Tool","reason":"its uninstaller did not finish in 600 s","keep":"keep"},` +
		`{"id":"hp-extras","name":"HP Extras\u0007","reason":"it is running and was left open","keep":"keep"},` +
		`{"id":"bad","name":"Bad","reason":"x","keep":"Not A Param!"},` +
		`"not an object"]}}`
	runRemoval(t, srv, result)

	v := getDecisions(t, srv)
	if len(v.Open) != 3 || v.Open[0].Group != "package:windows-software-removal" {
		t.Fatalf("open: %+v", v.Open)
	}
	byID := map[string]ownerDecision{}
	for _, d := range v.Open {
		byID[d.Item.ID] = d
	}
	if byID["hp-extras"].Item.Name != "HP Extras" || len(byID["bad"].Answers) != 1 || byID["bad"].Item.Keep != "" {
		t.Fatalf("items are not cleaned: %+v", byID)
	}

	// One record for the run, on the board (medium), with every item.
	findings, err := srv.decisionFindings(time.Now().UTC())
	if err != nil || len(findings) != 1 || findings[0].SeverityID != ocsfSevMedium ||
		!strings.Contains(findings[0].Message, "3 items waiting for your decision on 1 machine") {
		t.Fatalf("findings: %v %+v", err, findings)
	}
	if uid := findings[0].FindingInfo["uid"]; uid != "ominull.decisions.package.windows-software-removal" {
		t.Fatalf("uid %v", uid)
	}

	for body, want := range map[string]string{
		`{"key":"` + byID["wave-tool"].Key + `","answer":"keep"}`:                "reason",
		`{"key":"` + byID["bad"].Key + `","answer":"keep","reason":"x"}`:         "answer handled",
		`{"key":"nope","answer":"handled"}`:                                      "no open decision",
		`{"key":"` + byID["wave-tool"].Key + `","answer":"delete","reason":"x"}`: "keep or handled",
	} {
		if w := adminPost(srv, "/api/v1/maintenance/decisions", body, ""); w.Code == http.StatusOK || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	if w := adminPost(srv, "/api/v1/maintenance/decisions", `{"key":"`+byID["wave-tool"].Key+`","answer":"keep","reason":"the kids use it"}`, ""); w.Code != http.StatusOK {
		t.Fatalf("keep: %d %s", w.Code, w.Body.String())
	}
	rows, _ := srv.maintenanceRows("default")
	row := rows["windows-software-removal"]["ep-lap"]
	if row.Params["keep"] != "wave-tool" || !strings.Contains(row.Reason, "keeps Wave Tool: the kids use it") {
		t.Fatalf("override: %+v", row)
	}
	if w := adminPost(srv, "/api/v1/maintenance/decisions", `{"key":"`+byID["hp-extras"].Key+`","answer":"handled"}`, ""); w.Code != http.StatusOK {
		t.Fatalf("handled: %d %s", w.Code, w.Body.String())
	}
	if v := getDecisions(t, srv); len(v.Open) != 1 || len(v.Answered) != 2 {
		t.Fatalf("after answers: %+v", v)
	}
	if w := adminPost(srv, "/api/v1/maintenance/decisions", `{"key":"`+byID["bad"].Key+`","answer":"handled"}`, ""); w.Code != http.StatusOK {
		t.Fatalf("handled: %d %s", w.Code, w.Body.String())
	}
	findings, _ = srv.decisionFindings(time.Now().UTC())
	if len(findings) != 1 || findings[0].StatusID != ocsfStatusResolved {
		t.Fatalf("an answered run should read resolved: %+v", findings)
	}

	// The next run carries the machine's keep list; an item it reports again
	// (handled, but still there) opens again, the kept one is gone.
	time.Sleep(10 * time.Millisecond)
	settings, _ := srv.maintenanceSettings("default")
	defs, _ := srv.packageDefs("default")
	var h *scripts.PackageHeader
	for _, d := range defs {
		if d.Header.Name == "windows-software-removal" {
			h = d.Header
		}
	}
	if got := settings.Effective(h, "ep-lap").Params["keep"]; got != "wave-tool" {
		t.Fatalf("effective keep: %q", got)
	}
	runRemoval(t, srv, `{"v":1,"state":"drift","reboot":false,"changed":[],"detail":{"needs_owner":[{"id":"hp-extras","name":"HP Extras","reason":"it is running and was left open","keep":"keep"}]}}`)
	if v := getDecisions(t, srv); len(v.Open) != 1 || v.Open[0].Item.ID != "hp-extras" {
		t.Fatalf("reopened: %+v", v.Open)
	}
}
