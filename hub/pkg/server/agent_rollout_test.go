package server

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCanaryUpdateDoesNotPublishToOtherEndpoints(t *testing.T) {
	s, db := setupTestServer(t)
	defer db.Close()
	s.agentVersion = "1.2.0"
	if err := db.SetSetting("desired_agent_version", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	seedSignedRelease(t, s.binaryDir, "ominull-agent_1.2.0_amd64.deb")
	for _, id := range []string{"canary", "hold"} {
		seedEndpointWithCapability(t, db, id, "Linux", "1.1.0", "deb")
	}
	poll := func(id string) bool {
		t.Helper()
		r := httptest.NewRequest("GET", "/api/v1/agent/config?endpoint_id="+id, nil)
		r.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("poll: %d %s", w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		present, _ := body["update_available"].(bool)
		return present
	}
	if poll("hold") {
		t.Error("publishing a bundle offered an unrequested update")
	}
	r := httptest.NewRequest("POST", "/api/v1/agents/update", strings.NewReader(`{"endpoint_ids":["canary"],"version":"1.2.0"}`))
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("queue: %d %s", w.Code, w.Body.String())
	}
	if !poll("canary") {
		t.Error("selected canary has no update")
	}
	if poll("hold") {
		t.Error("canary request published update to unselected endpoint")
	}
}

func TestUpdateStatusUsesPublishedBundleAfterPreviousRollout(t *testing.T) {
	s, db := setupTestServer(t)
	defer db.Close()
	s.agentVersion = "1.2.0"
	if err := db.SetSetting("desired_agent_version", "1.1.0"); err != nil {
		t.Fatal(err)
	}
	seedEndpointWithCapability(t, db, "canary", "Linux", "1.1.0", "deb")
	r := httptest.NewRequest("GET", "/api/v1/agents/update-status", nil)
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var body struct {
		Latest   string              `json:"latest_version"`
		Outdated []map[string]string `json:"outdated"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Latest != "1.2.0" || len(body.Outdated) != 1 {
		t.Fatalf("previous fleet setting hid an outdated canary: %s", w.Body.String())
	}
}

func TestUpdateStatusDoesNotCallStaleEndpointOnline(t *testing.T) {
	s, db := setupTestServer(t)
	defer db.Close()
	seedEndpointWithCapability(t, db, "stale-agent", "Linux", "1.1.0", "deb")
	ep, err := db.GetEndpoint("stale-agent")
	if err != nil {
		t.Fatal(err)
	}
	ep.LastSeenAt = time.Now().Add(-time.Hour)
	ep.Status = "online"
	if err := db.UpsertEndpoint(*ep); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/agents/update-status", nil)
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var body struct {
		Endpoints []map[string]string `json:"endpoints"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Endpoints) != 1 || body.Endpoints[0]["status"] != "offline" {
		t.Fatalf("stale endpoint called online: %s", w.Body.String())
	}
}
