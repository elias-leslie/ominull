package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/scripts"
	"ominull/hub/pkg/storage"
)

func TestComplianceRecordShape(t *testing.T) {
	t.Parallel()
	at1, at2 := time.Date(2026, 10, 17, 3, 0, 0, 0, time.UTC), time.Date(2026, 10, 18, 3, 0, 0, 0, time.UTC)
	fails := func(prefix string, n int) []scripts.Control {
		var out []scripts.Control
		for i := 0; i < n; i++ {
			out = append(out, scripts.Control{ID: `HKLM:\Policies\` + prefix + string(rune('A'+i)), State: "fail"})
		}
		return out
	}
	ep := storage.Endpoint{ID: "windows-lap", Hostname: "laptop-1"}
	if complianceRecord(ep, []complianceRun{{Category: "maintenance", Run: &packageRun{CompletedAt: &at1}}}) != nil {
		t.Fatal("no controls, no record")
	}
	rec := complianceRecord(ep, []complianceRun{
		{Category: "maintenance", Run: &packageRun{CompletedAt: &at2, Controls: append(fails("M", 8), scripts.Control{ID: "x", State: "pass"}), Pass: 1, Fail: 8}},
		{Category: "security", Run: &packageRun{CompletedAt: &at1, Pass: 5, Fail: 3,
			Controls: append(fails("S", 2), scripts.Control{ID: `HKLM:\Policies\Lsa\RunAsPPL`, CIS: "CIS WIN11 2.3.1", State: "fail"})}},
	})
	failed := rec["failed"].([]string)
	if rec["at"] != "2026-10-18T03:00:00Z" || rec["security"] != (complianceCount{5, 3}) || rec["maintenance"] != (complianceCount{1, 8}) ||
		len(failed) != complianceFailedMax || failed[0] != "SA" || failed[2] != "CIS WIN11 2.3.1: RunAsPPL" || failed[3] != "MA" {
		t.Fatalf("record: %+v", rec)
	}
	raw, _ := json.Marshal(rec)
	if len(raw) > 4096 {
		t.Fatalf("a record must stay under the feed's 4 KB: %d", len(raw))
	}
	if complianceUID("Windows-LAPTOP.1") != "ominull.compliance.windows-laptop-1" {
		t.Fatal(complianceUID("Windows-LAPTOP.1"))
	}
}

// One record per machine from the latest finished run of each package that
// reported controls; a run in flight does not hide it; machines without
// controls and retired ones get none.
func TestComplianceFindings(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.responseEnabled = true
	authorityOf(t, srv)
	now := time.Now().UTC()
	for id, status := range map[string]string{"windows-lap": "online", "windows-old": "online", "windows-quiet": "online"} {
		if err := store.UpsertEndpoint(storage.Endpoint{ID: id, TenantID: "default", Hostname: strings.TrimPrefix(id, "windows-"), OS: "Windows 11 Home", Status: status, LastSeenAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	syncRealPackage(t, srv, "audit.ps1")
	syncRealPackage(t, srv, "privacy.ps1")
	run := func(eps string) {
		t.Helper()
		body := `{"endpoint_ids":[` + eps + `],"packages":["windows-audit","windows-privacy"],"mode":"audit"}`
		w := postAdmin(srv, "/api/v1/maintenance/run", body)
		if w.Code != http.StatusCreated {
			t.Fatalf("run: %d %s", w.Code, w.Body.String())
		}
	}
	run(`"windows-lap","windows-old"`)
	out := `{"v":1,"state":"drift","reboot":false,"changed":[],"detail":{"mode":"audit","controls":[` +
		`{"id":"HKLM:\\Software\\Policies\\Microsoft\\Windows\\DataCollection\\AllowTelemetry","expected":"1","actual":"3","state":"fail","risk":"safe"},` +
		`{"id":"HKLM:\\Software\\Policies\\Microsoft\\Windows\\System\\EnableActivityFeed","expected":"0","actual":"0","state":"pass","risk":"safe"}]}}`
	finishJobsWith(t, srv, "windows-lap", out)
	finishJobsWith(t, srv, "windows-old", out)
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "windows-old", TenantID: "default", Hostname: "old", OS: "Windows 11 Home", Status: "retired", LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	run(`"windows-lap"`) // in flight
	got, err := srv.complianceFindings(now.Add(time.Minute))
	if err != nil || len(got) != 1 {
		t.Fatalf("one machine has controls: %v %d %+v", err, len(got), got)
	}
	f := got[0]
	u := f.Unmapped
	if f.FindingInfo["uid"] != "ominull.compliance.windows-lap" || f.StatusID != ocsfStatusResolved || f.SeverityID != ocsfSevInformational ||
		len(f.Resources) != 1 || f.Resources[0].UID != "windows-lap" || u["hostname"] != "lap" ||
		u["maintenance"] != (complianceCount{2, 2}) || u["security"] != (complianceCount{}) {
		t.Fatalf("record: %+v", f)
	}
	if failed := u["failed"].([]string); len(failed) != 2 || failed[0] != "AllowTelemetry" {
		t.Fatalf("failed: %v", failed)
	}
	if _, err := time.Parse(time.RFC3339, u["at"].(string)); err != nil {
		t.Fatal(err)
	}
}
