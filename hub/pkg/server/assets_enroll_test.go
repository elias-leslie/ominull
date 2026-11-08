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
