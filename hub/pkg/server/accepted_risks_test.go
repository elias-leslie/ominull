package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

const acceptedAuditOut = `{"v":1,"state":"drift","reboot":false,"changed":[],"detail":{"mode":"audit","controls":[` +
	`{"id":"bitlocker","expected":"system drive protected","actual":"protection status 0","state":"fail","risk":"safe"},` +
	`{"id":"firewall","expected":"all profiles on","actual":"all profiles on","state":"pass","risk":"safe"}]}}`

func acceptRisk(srv *Server, ep string, accepted bool, reason string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]any{"endpoint_id": ep, "accept_risk": "bitlocker", "accepted": accepted, "reason": reason})
	return adminPut(srv, "/api/v1/maintenance/settings", string(b))
}

// Accepting a failing check on one machine: it reads Accepted (reason kept),
// leaves the score's counts, the drift list and the fix ask; accepting again
// elsewhere changes nothing there; un-accepting restores all of it.
func TestAcceptedRisk(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.responseEnabled = true
	now := time.Now().UTC()
	for _, id := range []string{"ep-kid", "ep-other"} {
		if err := store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: "default", Hostname: id, OS: "Windows 11 Home", Status: "online", LastSeenAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	// A machine with no result yet can take the decision (it may be offline).
	if w := acceptRisk(srv, "ep-nobody", true, "x"); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown machine: %d", w.Code)
	}
	audit, _ := syncRealPackage(t, srv, "audit.ps1")
	if w := adminPut(srv, "/api/v1/maintenance/settings", `{"package":"windows-audit","enabled":true,"on_drift":"enforce"}`); w.Code != http.StatusOK {
		t.Fatalf("on_drift: %d %s", w.Code, w.Body.String())
	}
	srv.runMaintenanceSchedules(now) // baseline audits
	finishJobsWith(t, srv, "ep-kid", acceptedAuditOut)
	finishJobsWith(t, srv, "ep-other", acceptedAuditOut)

	record := func(ep string) map[string]any {
		t.Helper()
		got, err := srv.complianceFindings(now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range got {
			if f.Resources[0].UID == ep {
				return f.Unmapped
			}
		}
		t.Fatalf("no record for %s", ep)
		return nil
	}
	if u := record("ep-kid"); u["maintenance"] != (complianceCount{1, 1}) || len(u["failed"].([]string)) != 1 {
		t.Fatalf("before: %+v", u)
	}

	w := acceptRisk(srv, "ep-kid", true, "Kids' gaming laptop, no sensitive data")
	if w.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", w.Code, w.Body.String())
	}
	var answer struct {
		Accepted []struct{ Control, Reason, By string } `json:"accepted_risks"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &answer)
	if len(answer.Accepted) != 1 || answer.Accepted[0].Control != "bitlocker" || answer.Accepted[0].Reason != "Kids' gaming laptop, no sensitive data" || answer.Accepted[0].By == "" {
		t.Fatalf("answer: %s", w.Body.String())
	}

	// Score input: no failure, one pass, the decision listed with its reason.
	u := record("ep-kid")
	acc := u["accepted"].([]map[string]string)
	if u["maintenance"] != (complianceCount{1, 0}) || len(u["failed"].([]string)) != 0 || len(acc) != 1 || acc[0]["title"] != "bitlocker" || acc[0]["reason"] == "" {
		t.Fatalf("accepted: %+v", u)
	}
	if u := record("ep-other"); u["maintenance"] != (complianceCount{1, 1}) {
		t.Fatalf("another machine changed: %+v", u)
	}

	// Device view: the run is clean and the control reads accepted.
	req := adminRequest(http.MethodGet, "/api/v1/maintenance?endpoint_id=ep-kid", "")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var view struct {
		Packages []struct{ Last *packageRun } `json:"packages"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	last := view.Packages[0].Last
	if last == nil || last.State != "ok" || last.Fail != 0 || last.Controls[0].State != "accepted" || last.Controls[0].Accepted.Reason == "" {
		t.Fatalf("device view: %s", rec.Body.String())
	}

	// Fleet maintenance record: nothing needs changes for the accepted machine.
	fs, err := srv.maintenanceFindings(now.Add(time.Minute))
	if err != nil || fs[0].Unmapped["needs_changes"] != 1 {
		t.Fatalf("one machine still drifts: %v %+v", err, fs[0].Unmapped)
	}

	// No fix run for the accepted machine, one for the other.
	later := now.Add(10 * time.Minute)
	for _, id := range []string{"ep-kid", "ep-other"} {
		_ = store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: "default", Hostname: id, OS: "Windows 11 Home", Status: "online", LastSeenAt: later})
	}
	srv.runMaintenanceSchedules(later)
	runs := func(ep string) int {
		list, err := srv.responseStore.ScriptJobs("default", ep, audit.ID, 50)
		if err != nil {
			t.Fatal(err)
		}
		return len(list)
	}
	if runs("ep-kid") != 1 || runs("ep-other") != 2 {
		t.Fatalf("only the machine that did not accept gets the fix run: kid %d, other %d jobs", runs("ep-kid"), runs("ep-other"))
	}

	// Un-accept restores everything.
	if w := acceptRisk(srv, "ep-kid", false, ""); w.Code != http.StatusOK {
		t.Fatalf("unaccept: %d", w.Code)
	}
	if u := record("ep-kid"); u["maintenance"] != (complianceCount{1, 1}) || len(u["failed"].([]string)) != 1 || len(u["accepted"].([]map[string]string)) != 0 {
		t.Fatalf("after: %+v", u)
	}
	logs, _ := store.ListAuditLogs("", 50)
	seen := map[string]bool{}
	for _, l := range logs {
		seen[l.Action+" "+l.Resource] = true
	}
	if !seen["RISK_ACCEPTED ep-kid"] || !seen["RISK_ACCEPTANCE_REMOVED ep-kid"] {
		t.Fatalf("audit: %v", seen)
	}
}
