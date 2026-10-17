package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
)

// Maintenance mode: each host gets its platform's package, the card reads
// on/until from the latest run, an end time already past reads as off, and
// the schedule never runs it.
func TestMaintenanceModeState(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	srv.responseEnabled = true
	now := time.Now().UTC()
	for _, ep := range []storage.Endpoint{
		{ID: "ep-lap", TenantID: "default", Hostname: "laptop-1", OS: "Windows 11 Home", Status: "online", LastSeenAt: now},
		{ID: "ep-srv", TenantID: "default", Hostname: "srv-1", OS: "linux", Status: "online", LastSeenAt: now},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}
	win, _ := syncRealPackage(t, srv, "maintenance-mode.ps1")
	lin, _ := syncRealPackage(t, srv, "linux/maintenance-mode.sh")
	if lin.Interpreter != "/bin/sh" || win.Interpreter != "powershell.exe" {
		t.Fatalf("interpreters: %s %s", lin.Interpreter, win.Interpreter)
	}

	type view struct {
		Packages        []packageStatus      `json:"packages"`
		MaintenanceMode *maintenanceModeView `json:"maintenance_mode"`
	}
	get := func(ep string) view {
		t.Helper()
		rec := httptest.NewRecorder()
		srv.handleMaintenance(rec, httptest.NewRequest("GET", "/api/v1/maintenance?endpoint_id="+ep, nil))
		var v view
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
			t.Fatalf("maintenance %s: %d %s", ep, rec.Code, rec.Body.String())
		}
		return v
	}
	v := get("ep-srv")
	if m := v.MaintenanceMode; m == nil || m.Package != "linux-maintenance-mode" || m.On || m.Hours != 6 || m.Last != nil {
		t.Fatalf("linux host before any run: %+v", m)
	}
	if len(v.Packages) != 1 || v.Packages[0].Role != "maintenance_mode" {
		t.Fatalf("linux host packages: %+v", v.Packages)
	}
	if m := get("ep-lap").MaintenanceMode; m == nil || m.Package != "windows-maintenance-mode" {
		t.Fatalf("windows host: %+v", m)
	}

	// A default audit of a safe released package runs without a tap, on Linux too.
	w := adminPost(srv, "/api/v1/maintenance/run", `{"endpoint_ids":["ep-srv"],"packages":["linux-maintenance-mode"],"mode":"audit"}`, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("linux audit: %d %s", w.Code, w.Body.String())
	}
	if m := get("ep-srv").MaintenanceMode; m.Pending != "check" || m.On {
		t.Fatalf("while the audit waits: %+v", m)
	}
	complete := func(ep, stdout string) {
		t.Helper()
		offers, err := srv.responseStore.OfferPendingJobs("default", ep, 4, time.Minute)
		if err != nil || len(offers) != 1 {
			t.Fatalf("offer: %v %d", err, len(offers))
		}
		var p response.ScriptExecPayload
		if json.Unmarshal([]byte(offers[0].PayloadJSON), &p) != nil || p.Interpreter != "/bin/sh" || p.Parameters["hours"] != "6" {
			t.Fatalf("linux payload: %s", offers[0].PayloadJSON)
		}
		if err := srv.responseStore.AcknowledgeJob("default", ep, offers[0].JobID, offers[0].LeaseID, true, ""); err != nil {
			t.Fatal(err)
		}
		if err := srv.responseStore.CompleteJob("default", ep, offers[0].JobID, offers[0].LeaseID, &response.JobResult{
			JobID: offers[0].JobID, LeaseID: offers[0].LeaseID, State: response.StateSucceeded, Stdout: stdout}); err != nil {
			t.Fatal(err)
		}
	}
	until := now.Add(5 * time.Hour).Truncate(time.Second)
	complete("ep-srv", `{"v":1,"state":"ok","reboot":false,"changed":[],"detail":{"mode":"audit","maintenance_mode":{"on":true,"until":"`+until.Format(time.RFC3339)+`"}}}`)
	if m := get("ep-srv").MaintenanceMode; !m.On || m.Until == nil || !m.Until.Equal(until) || m.Pending != "" {
		t.Fatalf("after an audit that saw it on: %+v", m)
	}

	// An end already past reads as off.
	job := &response.JobRecord{ID: "j", State: response.StateSucceeded, ResultJSON: `{"stdout":"{\"v\":1,\"state\":\"fixed\",\"reboot\":false,\"changed\":[],\"detail\":{\"maintenance_mode\":{\"on\":true,\"until\":\"2026-01-01T00:00:00.1234567Z\"}}}"}`}
	m := &maintenanceModeView{}
	maintenanceModeState(m, job, now)
	if m.On || m.Last == nil || m.Last.State != "fixed" {
		t.Fatalf("expired: %+v", m)
	}
	// Windows writes seven fractional digits; that still parses.
	m = &maintenanceModeView{}
	maintenanceModeState(m, job, time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC))
	if !m.On || m.Until == nil {
		t.Fatalf("fractional until: %+v", m)
	}

	// Enabled in the settings, the schedule still never runs it.
	if w := adminPut(srv, "/api/v1/maintenance/settings", `{"package":"linux-maintenance-mode","enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", w.Code, w.Body.String())
	}
	srv.runMaintenanceSchedules(now.Add(48 * time.Hour))
	if n := len(get("ep-srv").Packages); n != 1 {
		t.Fatal(n)
	}
	if offers, _ := srv.responseStore.OfferPendingJobs("default", "ep-srv", 4, time.Minute); len(offers) != 0 {
		t.Fatalf("the schedule ran maintenance mode: %d jobs", len(offers))
	}
}
