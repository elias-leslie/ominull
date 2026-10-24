package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/response"
)

// Nightshift confirms its locks with the relay key: only machines that carry
// a lock are listed, a machine whose agent started before host_authority.json
// existed shows host_file false, and the fleet view says host_authority false
// rather than leaving the field out.
func TestNightshiftLocks(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, id := range []string{"ep-gem", "ep-ws", "ep-lap"} {
		seedPlainEndpoints(t, store, id)
	}
	srv.trust.mu.Lock()
	srv.trust.init()
	srv.trust.reports["ep-gem"] = trustReportSeen{at: time.Now(), report: response.AgentTrustReport{V: 1, Ceiling: "monitor-signed-scripts", Profile: "monitor",
		HostAuthority: true, HostKeys: []response.HostKeyReport{{ID: strings.Repeat("ab", 32), Role: "tap"}}}}
	srv.trust.reports["ep-ws"] = trustReportSeen{at: time.Now().Add(-20 * time.Minute), report: response.AgentTrustReport{V: 1, Ceiling: "signed-scripts", Profile: "respond"}}
	srv.trust.reports["ep-lap"] = trustReportSeen{at: time.Now(), report: response.AgentTrustReport{V: 1, Profile: "respond"}}
	srv.trust.mu.Unlock()

	issue := postAdmin(srv, "/api/v1/integrations/nightshift/approval-key", ``)
	var k struct {
		Key string `json:"key"`
	}
	_ = json.Unmarshal(issue.Body.Bytes(), &k)
	get := func(path, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-API-Key", key)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	if w := get("/api/v1/integrations/nightshift/locks", "mock_admin_token"); w.Code != http.StatusUnauthorized {
		t.Fatalf("admin key on the relay route: %d", w.Code)
	}
	w := get("/api/v1/integrations/nightshift/locks", k.Key)
	if w.Code != http.StatusOK {
		t.Fatalf("locks: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Endpoints []map[string]any `json:"endpoints"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	got := map[string]map[string]any{}
	for _, r := range out.Endpoints {
		got[r["endpoint_id"].(string)] = r
	}
	if len(got) != 2 || got["ep-lap"] != nil {
		t.Fatalf("want only the locked machines: %s", w.Body.String())
	}
	if g := got["ep-gem"]; g["host_authority"] != true || g["host_file"] != true || g["stale"] != false {
		t.Fatalf("gem: %v", g)
	}
	if ws := got["ep-ws"]; ws["host_authority"] != false || ws["host_file"] != false || ws["stale"] != true || ws["ceiling"] != "signed-scripts" {
		t.Fatalf("workstation: %v", ws)
	}
	if strings.Contains(w.Body.String(), "ed25519") {
		t.Fatalf("locks carry key material: %s", w.Body.String())
	}

	fleet := get("/api/v1/fleet/trust", "mock_admin_token")
	var f struct {
		Endpoints []map[string]any `json:"endpoints"`
	}
	_ = json.Unmarshal(fleet.Body.Bytes(), &f)
	for _, r := range f.Endpoints {
		if r["endpoint_id"] == "ep-ws" {
			if v, ok := r["host_authority"]; !ok || v != false {
				t.Fatalf("fleet view hides host_authority false: %v", r)
			}
		}
	}
}
