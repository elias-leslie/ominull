package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// Nightshift reads every active agent's build with the relay key: offline
// ones stay, retired ones go, and the admin key is not the relay key.
func TestNightshiftAgentBuilds(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, ep := range []storage.Endpoint{
		{ID: "ep-new", TenantID: "default", Hostname: "host-new", OS: "test", Status: "online", DriverVersion: "1.8.73", LastSeenAt: time.Now()},
		{ID: "ep-old", TenantID: "default", Hostname: "host-old", OS: "test", Status: "offline", DriverVersion: "1.8.67", LastSeenAt: time.Now().Add(-72 * time.Hour)},
		{ID: "ep-gone", TenantID: "default", Hostname: "host-gone", OS: "test", Status: "retired", DriverVersion: "1.8.1"},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}
	issue := adminPost(srv, "/api/v1/integrations/nightshift/approval-key", ``, "")
	var k struct {
		Key string `json:"key"`
	}
	_ = json.Unmarshal(issue.Body.Bytes(), &k)
	get := func(key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/v1/integrations/nightshift/agent-builds", nil)
		req.Header.Set("X-API-Key", key)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}
	if w := get("mock_admin_token"); w.Code != http.StatusUnauthorized {
		t.Fatalf("admin key on the relay route: %d", w.Code)
	}
	w := get(k.Key)
	if w.Code != http.StatusOK {
		t.Fatalf("builds: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Endpoints []nightshiftBuildRow `json:"endpoints"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if len(out.Endpoints) != 2 || out.Endpoints[0].EndpointID != "ep-new" || out.Endpoints[0].AgentVersion != "1.8.73" ||
		out.Endpoints[1].EndpointID != "ep-old" || out.Endpoints[1].AgentVersion != "1.8.67" || out.Endpoints[1].LastSeen == "" {
		t.Fatalf("want the two active agents, new first: %s", w.Body.String())
	}
}
