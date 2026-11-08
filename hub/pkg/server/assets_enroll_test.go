package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

// A machine appears in the assets list as soon as its endpoint row exists: the
// console has no fallback that builds rows from the endpoint list.
func TestEnrolledEndpointIsAnAssetAtOnce(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "ep-new", TenantID: "default", Hostname: "new-box", OS: "Windows 11 Home", IP: "10.0.0.8", Status: "online", LastSeenAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/assets", nil)
	req.Header.Set("X-Role", "admin")
	w := httptest.NewRecorder()
	srv.handleAssets(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var rows []struct {
		ID              string `json:"id"`
		AgentEndpointID string `json:"agent_endpoint_id"`
		Hostname        string `json:"hostname"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.AgentEndpointID == "ep-new" && r.Hostname == "new-box" {
			return
		}
	}
	t.Fatalf("the new endpoint has no asset row: %s", w.Body.String())
}

// A login tied to a client sees that client's enrolled machines and nobody else's,
// whatever it asks for; a client with none gets an empty list, not an error.
func TestScopedLoginSeesItsOwnEnrolledMachines(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, ep := range []storage.Endpoint{
		{ID: "ep-a", TenantID: "t-a", Hostname: "box-a", OS: "Linux", IP: "10.0.0.8", Status: "online"},
		{ID: "ep-b", TenantID: "t-b", Hostname: "box-b", OS: "Linux", IP: "10.0.0.9", Status: "online"},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}
	list := func(tenant string) []string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/assets?tenant_id=t-b", nil)
		req.Header.Set("X-Role", "operator")
		req.Header.Set("X-Tenant-ID", tenant)
		w := httptest.NewRecorder()
		srv.handleAssets(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
		var rows []struct {
			AgentEndpointID string `json:"agent_endpoint_id"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, r := range rows {
			got = append(got, r.AgentEndpointID)
		}
		return got
	}
	if got := list("t-a"); len(got) != 1 || got[0] != "ep-a" {
		t.Fatalf("client t-a sees %v", got)
	}
	if got := list("t-empty"); len(got) != 0 {
		t.Fatalf("a client with no machines sees %v", got)
	}
}
