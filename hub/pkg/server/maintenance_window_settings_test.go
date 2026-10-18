package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/storage"
)

// Per-machine maintenance windows: a fleet default (shipped 01:00-05:00
// machine time), per-machine windows in machine time or UTC, each run
// carrying its machine's window, and the next start once the machine's
// offset is known.
func TestMaintenanceWindowsPerMachine(t *testing.T) {
	t.Parallel()
	srv := playbookTestServer(t)
	if err := srv.store.UpsertEndpoint(storage.Endpoint{ID: "ep-desk", TenantID: "default", Hostname: "desk-1", OS: "Windows 11 Pro", Status: "online", LastSeenAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	get := func(q string) map[string]interface{} {
		t.Helper()
		w := adminDo(srv, http.MethodGet, "/api/v1/maintenance/windows"+q, "")
		var m map[string]interface{}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &m) != nil {
			t.Fatalf("get %s: %d %s", q, w.Code, w.Body.String())
		}
		return m
	}
	if m := get("?endpoint_id=ep-lap"); m["source"] != "default" || m["clock"] != "machine" || m["next_start"] != nil {
		t.Fatalf("default: %v", m)
	}
	for body, want := range map[string]string{
		`{"ranges":["25:00-01:00"]}`:               "HH:MM",
		`{"ranges":["01:00-02:00"],"clock":"hub"}`: "clock",
		`{}`: "reset",
		`{"ranges":["01:00-02:00"],"reset":true}`:            "reset",
		`{"ranges":["1","2","3","4","5"]}`:                   "1 to 4",
		`{"endpoint_id":"ep-gone","ranges":["01:00-02:00"]}`: "not found",
	} {
		w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/windows", body)
		if w.Code == http.StatusOK || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d %s", body, w.Code, w.Body.String())
		}
	}
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/windows", `{"ranges":["22:00-02:00","12:00-13:00"]}`); w.Code != http.StatusOK {
		t.Fatalf("fleet: %d %s", w.Code, w.Body.String())
	}
	if w := adminDo(srv, http.MethodPut, "/api/v1/maintenance/windows?endpoint_id=ep-desk", `{"ranges":["03:00-04:00"],"clock":"utc"}`); w.Code != http.StatusOK {
		t.Fatalf("desk: %d %s", w.Code, w.Body.String())
	}
	if m := get("?endpoint_id=ep-desk"); m["source"] != "endpoint" || m["clock"] != "utc" || m["next_start"] == nil {
		t.Fatalf("desk view: %v", m)
	}
	if m := get(""); len(m["endpoints"].(map[string]interface{})) != 1 || m["default"].(map[string]interface{})["source"] != "fleet" {
		t.Fatalf("fleet view: %v", m)
	}

	// Each run carries its machine's window; machines whose windows differ
	// cannot share one run.
	tenant := "default"
	settings, _ := srv.maintenanceSettings(tenant)
	sc, _ := srv.findPackage(tenant, "windows-cleanup")
	for ep, want := range map[string]string{"ep-lap": "22:00-02:00,12:00-13:00", "ep-desk": "03:00-04:00Z"} {
		hosts, _ := srv.packageHosts(tenant, []string{ep})
		it, _, err := srv.buildPackageItem(tenant, sc, "enforce", []string{ep}, hosts, settings, nil)
		if err != nil {
			t.Fatal(err)
		}
		var p response.ScriptExecPayload
		_ = json.Unmarshal([]byte(it.Raw), &p)
		if p.Parameters["window"] != want {
			t.Errorf("%s window %q, want %q", ep, p.Parameters["window"], want)
		}
	}
	both, _ := srv.packageHosts(tenant, []string{"ep-desk", "ep-lap"})
	if _, _, err := srv.buildPackageItem(tenant, sc, "enforce", []string{"ep-desk", "ep-lap"}, both, settings, nil); err == nil || !strings.Contains(err.Error(), "separately") {
		t.Fatalf("differing windows in one run: %v", err)
	}

	// Machine time: the hub can tell only once the machine reports its offset.
	noon := time.Date(2026, 10, 17, 12, 30, 0, 0, time.UTC)
	if !srv.windowOpenOrUnknown("01:00-02:00", "ep-lap", noon) {
		t.Fatal("unknown offset must leave the decision to the package")
	}
	off := 120
	srv.trust.mu.Lock()
	srv.trust.init()
	srv.trust.reports["ep-lap"] = trustReportSeen{report: response.AgentTrustReport{V: 1, UTCOffset: &off}, at: time.Now()}
	srv.trust.mu.Unlock()
	if srv.windowOpenOrUnknown("01:00-02:00", "ep-lap", noon) || !srv.windowOpenOrUnknown("14:00-15:00", "ep-lap", noon) {
		t.Fatal("known offset: 12:30 UTC is 14:30 machine time")
	}
	if m := get("?endpoint_id=ep-lap"); m["utc_offset_minutes"] != float64(120) || m["next_start"] == nil {
		t.Fatalf("offset view: %v", m)
	}

	// Reset: the machine follows the fleet, the fleet the shipped default.
	adminDo(srv, http.MethodPut, "/api/v1/maintenance/windows?endpoint_id=ep-desk", `{"reset":true}`)
	adminDo(srv, http.MethodPut, "/api/v1/maintenance/windows", `{"reset":true}`)
	if m := get("?endpoint_id=ep-desk"); m["source"] != "default" || m["ranges"].([]interface{})[0] != "01:00-05:00" {
		t.Fatalf("after reset: %v", m)
	}
}
