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

// A hypervisor is never isolated at host level: an operator's monitor-only
// setting, the hypervisor role and an agent that says it cannot isolate each
// make the hub refuse before it even asks the owner. The OS name plays no part.
func TestMonitorOnlyRefusesHostIsolation(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-pve", ResponseCapabilities: `{"isolate":true,"collect":true}`})
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-role", RoleTag: "Hypervisor"})
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-cant", ResponseCapabilities: `{"isolate":false,"collect":true}`})
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-guest", ResponseCapabilities: `{"isolate":true}`})
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-old"}) // agent that reports no capabilities
	monitorOnly(t, srv, "ep-pve")

	for _, id := range []string{"ep-pve", "ep-role", "ep-cant"} {
		w := adminPost(srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"`+id+`","force":true}`, "")
		if w.Code != http.StatusConflict {
			t.Fatalf("%s: want 409 monitor-only, got %d %s", id, w.Code, w.Body.String())
		}
		var body struct {
			MonitorOnly []string `json:"monitor_only"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if len(body.MonitorOnly) != 1 || body.MonitorOnly[0] != id {
			t.Fatalf("%s: refusal names %v", id, body.MonitorOnly)
		}
		if isolated(t, store, id) {
			t.Fatalf("%s isolated", id)
		}
		ep, _ := store.GetEndpoint(id)
		if !ep.MonitorOnly || ep.MonitorOnlyReason() == "" {
			t.Fatalf("%s: monitor_only=%v reason=%q", id, ep.MonitorOnly, ep.MonitorOnlyReason())
		}
	}
	// Ordinary endpoints still go to the owner.
	for _, id := range []string{"ep-guest", "ep-old"} {
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
// directly), a bulk SQL update skips monitor-only rows, and an isolation that
// was recorded before the endpoint became monitor-only is never sent to it.
func TestStoreNeverIsolatesMonitorOnly(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedPlain(t, store, "ep-1", "ep-pve", "ep-pve2")
	if err := store.SetEndpointIsolation("ep-pve2", true, nil); err != nil {
		t.Fatal(err)
	}
	monitorOnly(t, srv, "ep-pve")
	monitorOnly(t, srv, "ep-pve2")

	if err := store.SetEndpointIsolation("ep-pve", true, nil); !errors.Is(err, storage.ErrMonitorOnly) {
		t.Fatalf("store isolated a monitor-only endpoint: %v", err)
	}
	if err := store.SetEndpointIsolation("no-such", true, nil); err != nil {
		t.Fatalf("unknown id: %v", err)
	}
	n, err := store.SetBulkIsolation("", "all", "", true, nil)
	if err != nil || n != 1 {
		t.Fatalf("bulk SQL isolation: n=%d err=%v", n, err)
	}
	if isolated(t, store, "ep-pve") || !isolated(t, store, "ep-1") {
		t.Fatal("bulk SQL isolation touched a monitor-only endpoint")
	}
	iso, _, err := store.GetEndpointIsolation("ep-pve2")
	if err != nil || iso {
		t.Fatalf("monitor-only endpoint told to isolate: %v %v", iso, err)
	}
	if iso, _, _ := store.GetEndpointIsolation("ep-1"); !iso {
		t.Fatal("ordinary isolation not sent")
	}
	// Release still works on a monitor-only endpoint.
	if err := store.SetEndpointIsolation("ep-pve2", false, nil); err != nil || isolated(t, store, "ep-pve2") {
		t.Fatalf("release: %v", err)
	}
}

// Lifting monitor-only is a capability raise: it takes the owner's approval,
// and a hypervisor role keeps the endpoint monitor-only regardless.
func TestAllowIsolationNeedsTheOwner(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	seedPlain(t, store, "ep-pve")
	seedEndpointRow(t, store, storage.Endpoint{ID: "ep-role", RoleTag: "hypervisor"})
	monitorOnly(t, srv, "ep-pve")
	monitorOnly(t, srv, "ep-role")

	body := `{"endpoint_id":"ep-pve","reason":"no longer a hypervisor"}`
	id := pendingID(t, adminPost(srv, "/api/v1/endpoints/allow-isolation", body, ""))
	if ep, _ := store.GetEndpoint("ep-pve"); !ep.MonitorOnly {
		t.Fatal("lifted before the owner approved")
	}
	ownerOf(t, srv).approve(t, id)
	if w := adminPost(srv, "/api/v1/endpoints/allow-isolation", `{"endpoint_id":"ep-role","reason":"x"}`, id); w.Code != http.StatusForbidden {
		t.Fatalf("approval for ep-pve used on ep-role: %d %s", w.Code, w.Body.String())
	}
	if w := adminPost(srv, "/api/v1/endpoints/allow-isolation", body, id); w.Code != http.StatusOK {
		t.Fatalf("approved lift: %d %s", w.Code, w.Body.String())
	}
	if ep, _ := store.GetEndpoint("ep-pve"); ep.MonitorOnly || ep.ResponseProfile != "" {
		t.Fatalf("still monitor-only after the lift: %+v", ep)
	}
	if w := adminPost(srv, "/api/v1/endpoints/isolate", `{"endpoint_id":"ep-pve","force":true}`, ""); w.Code != http.StatusAccepted {
		t.Fatalf("isolation after lift: %d", w.Code)
	}

	rb := `{"endpoint_id":"ep-role","reason":"try"}`
	w := serveApproved(t, srv, srv.Handler(), adminRequest("POST", "/api/v1/endpoints/allow-isolation", rb), rb)
	var out struct {
		MonitorOnly bool   `json:"monitor_only"`
		Still       string `json:"still_monitor_only"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != http.StatusOK || !out.MonitorOnly || out.Still == "" {
		t.Fatalf("hypervisor role lift: %d %s", w.Code, w.Body.String())
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
