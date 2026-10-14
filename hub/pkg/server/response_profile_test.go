package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ominull/hub/pkg/storage"
)

func seedEndpointRow(t *testing.T, store *storage.Store, ep storage.Endpoint) {
	t.Helper()
	if ep.TenantID == "" {
		ep.TenantID = "default"
	}
	if ep.Hostname == "" {
		ep.Hostname = "host-" + ep.ID
	}
	ep.OS, ep.Status = "Linux", "online"
	if err := store.UpsertEndpoint(ep); err != nil {
		t.Fatal(err)
	}
}

func monitorOnly(t *testing.T, srv *Server, id string) {
	t.Helper()
	if w := adminPost(srv, "/api/v1/endpoints/monitor-only", `{"endpoint_id":"`+id+`","reason":"hypervisor"}`, ""); w.Code != http.StatusOK {
		t.Fatalf("monitor-only %s: %d %s", id, w.Code, w.Body.String())
	}
}

// A hypervisor is never isolated at host level once an operator made it
// monitor-only. What an endpoint says about itself (its role tag, an agent
// reporting it cannot isolate) never decides: it arrives with every heartbeat.
// The OS name plays no part either.
func TestMonitorOnlyRefusesHostIsolation(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-pve", ResponseCapabilities: `{"isolate":true,"collect":true}`})
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-role", RoleTag: "Hypervisor"})
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-cant", ResponseCapabilities: `{"isolate":false,"collect":true}`})
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-old"}) // agent that reports no capabilities
	monitorOnly(t, srv, "ep-pve")

	w := adminPost(srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-pve","force":true}`, "")
	if w.Code != http.StatusConflict {
		t.Fatalf("want 409 monitor-only, got %d %s", w.Code, w.Body.String())
	}
	var body struct {
		MonitorOnly []string `json:"monitor_only"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if len(body.MonitorOnly) != 1 || body.MonitorOnly[0] != "ep-pve" || isolated(t, store, "ep-pve") {
		t.Fatalf("refusal names %v", body.MonitorOnly)
	}
	if ep, _ := store.GetEndpoint("ep-pve"); !ep.MonitorOnly || ep.MonitorOnlyReason() == "" || ep.ResponseProfileRev != 1 {
		t.Fatalf("ep-pve: %+v", ep)
	}
	// Self-labelled endpoints still go to the owner.
	for _, id := range []string{"ep-role", "ep-cant", "ep-old"} {
		if w := adminPost(srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"`+id+`","force":true}`, ""); w.Code != http.StatusAccepted {
			t.Fatalf("%s: want 202 approval, got %d %s", id, w.Code, w.Body.String())
		}
		if ep, _ := store.GetEndpoint(id); ep.MonitorOnly {
			t.Fatalf("%s reported monitor-only", id)
		}
	}
	logs, _ := store.ListAuditLogs("", 100)
	found := false
	for _, l := range logs {
		found = found || (l.Action == "ENDPOINT_MONITOR_ONLY_SET" && l.Resource == "ep-pve")
	}
	if !found {
		t.Fatal("no ENDPOINT_MONITOR_ONLY_SET audit")
	}
}

// Bulk isolation leaves monitor-only endpoints out of the approval and the
// change, and says so; a bulk of only monitor-only hosts is refused.
func TestBulkIsolationLeavesMonitorOnlyOut(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedPlain(t, store, "ep-1", "ep-pve")
	monitorOnly(t, srv, "ep-pve")

	body := `{"scope":"all","force":true}`
	w := serveApproved(t, srv, srv.Handler(), adminRequest("POST", "/api/v1/endpoints/isolate-bulk", body), body)
	if w.Code != http.StatusOK {
		t.Fatalf("bulk isolate: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Affected int64    `json:"affected_endpoints"`
		Excluded []string `json:"excluded_monitor_only"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Affected != 1 || len(out.Excluded) != 1 || out.Excluded[0] != "ep-pve" {
		t.Fatalf("bulk reply %s", w.Body.String())
	}
	if !isolated(t, store, "ep-1") || isolated(t, store, "ep-pve") {
		t.Fatal("bulk isolation touched the wrong hosts")
	}
	only := `{"scope":"ids","ids":["ep-pve"],"force":true}`
	if w := adminPost(srv, "/api/v1/endpoints/isolate-bulk", only, ""); w.Code != http.StatusConflict {
		t.Fatalf("bulk of monitor-only hosts: %d %s", w.Code, w.Body.String())
	}
}

// The store refuses whoever asks (the detector's automatic isolation calls it
// directly) and a bulk SQL update skips monitor-only rows. An isolated
// endpoint cannot be made monitor-only: that would release it without the owner.
func TestStoreNeverIsolatesMonitorOnly(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedPlain(t, store, "ep-1", "ep-pve", "ep-pve2")
	if err := store.SetEndpointIsolation("ep-pve2", true, []string{"10.0.0.5"}); err != nil {
		t.Fatal(err)
	}
	monitorOnly(t, srv, "ep-pve")
	if w := adminPost(srv, "/api/v1/endpoints/monitor-only", `{"endpoint_id":"ep-pve2","reason":"hypervisor"}`, ""); w.Code != http.StatusConflict {
		t.Fatalf("monitor-only on an isolated endpoint: %d %s", w.Code, w.Body.String())
	}
	if iso, ips, _ := store.GetEndpointIsolation("ep-pve2"); !iso || len(ips) != 1 {
		t.Fatalf("isolation of ep-pve2 changed: %v %v", iso, ips)
	}

	if err := store.SetEndpointIsolation("ep-pve", true, nil); !errors.Is(err, storage.ErrMonitorOnly) {
		t.Fatalf("store isolated a monitor-only endpoint: %v", err)
	}
	if err := store.SetEndpointIsolation("no-such", true, nil); err != nil {
		t.Fatalf("unknown id: %v", err)
	}
	n, err := store.SetBulkIsolation("", "all", "", true, nil)
	if err != nil || n != 2 {
		t.Fatalf("bulk SQL isolation: n=%d err=%v", n, err)
	}
	if isolated(t, store, "ep-pve") || !isolated(t, store, "ep-1") {
		t.Fatal("bulk SQL isolation touched a monitor-only endpoint")
	}
	if iso, _, _ := store.GetEndpointIsolation("ep-1"); !iso {
		t.Fatal("ordinary isolation not sent")
	}
}

// Lifting monitor-only is a capability raise: it takes the owner's approval,
// for the revision of the setting the owner was shown.
func TestAllowIsolationNeedsTheOwner(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedPlain(t, store, "ep-pve", "ep-other")
	monitorOnly(t, srv, "ep-pve")
	monitorOnly(t, srv, "ep-other")

	if w := adminPost(srv, "/api/v1/endpoints/allow-isolation", `{"endpoint_id":"ep-pve","reason":"x"}`, ""); w.Code != http.StatusConflict {
		t.Fatalf("lift without a revision: %d %s", w.Code, w.Body.String())
	}
	body := `{"endpoint_id":"ep-pve","reason":"no longer a hypervisor","revision":1}`
	id := pendingID(t, adminPost(srv, "/api/v1/endpoints/allow-isolation", body, ""))
	if ep, _ := store.GetEndpoint("ep-pve"); !ep.MonitorOnly {
		t.Fatal("lifted before the owner approved")
	}
	ownerOf(t, srv).approve(t, id)
	if w := adminPost(srv, "/api/v1/endpoints/allow-isolation", `{"endpoint_id":"ep-other","reason":"x","revision":1}`, id); w.Code != http.StatusForbidden {
		t.Fatalf("approval for ep-pve used on ep-other: %d %s", w.Code, w.Body.String())
	}
	if w := adminPost(srv, "/api/v1/endpoints/allow-isolation", body, id); w.Code != http.StatusOK {
		t.Fatalf("approved lift: %d %s", w.Code, w.Body.String())
	}
	if ep, _ := store.GetEndpoint("ep-pve"); ep.MonitorOnly || ep.ResponseProfile != "" || ep.ResponseProfileRev != 2 {
		t.Fatalf("still monitor-only after the lift: %+v", ep)
	}
	if w := adminPost(srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-pve","force":true}`, ""); w.Code != http.StatusAccepted {
		t.Fatalf("isolation after lift: %d", w.Code)
	}

	// An older approved lift cannot erase a newer monitor-only decision.
	monitorOnly(t, srv, "ep-pve") // revision 3
	if _, err := store.LiftMonitorOnly("ep-pve", 1); !errors.Is(err, storage.ErrProfileChanged) {
		t.Fatalf("stale revision lifted the setting: %v", err)
	}
	stale := `{"endpoint_id":"ep-pve","reason":"again","revision":1}`
	w := serveApproved(t, srv, srv.Handler(), adminRequest("POST", "/api/v1/endpoints/allow-isolation", stale), stale)
	if w.Code != http.StatusConflict {
		t.Fatalf("approval for revision 1 at revision 3: %d %s", w.Code, w.Body.String())
	}
	if ep, _ := store.GetEndpoint("ep-pve"); !ep.MonitorOnly || ep.ResponseProfileRev != 3 {
		t.Fatalf("newer setting erased: %+v", ep)
	}
	// Setting monitor-only needs admin, and a reason.
	if w := adminPost(srv, "/api/v1/endpoints/monitor-only", `{"endpoint_id":"ep-pve"}`, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("monitor-only without a reason: %d", w.Code)
	}
}

func adminRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	return req
}
