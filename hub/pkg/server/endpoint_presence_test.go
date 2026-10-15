package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func postPresence(srv *Server, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/presence", bytes.NewBufferString(body))
	req.Header.Set("X-API-Key", token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestEndpointPresenceNeedsAReasonAndAKnownHost(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	if err := store.UpsertEndpoint(storage.Endpoint{ID: "lt", TenantID: "t-01", Hostname: "lt", Status: "online", LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	for body, want := range map[string]int{
		`{"endpoint_id":"lt","presence":"intermittent"}`:                http.StatusBadRequest,
		`{"endpoint_id":"lt","presence":"sometimes","reason":"x"}`:      http.StatusBadRequest,
		`{"endpoint_id":"nope","presence":"lab","reason":"test guest"}`: http.StatusNotFound,
	} {
		if w := postPresence(srv, "mock_admin_token", body); w.Code != want {
			t.Fatalf("%s = %d %s, want %d", body, w.Code, w.Body.String(), want)
		}
	}
	// Watching a host less closely waits for the owner's tap.
	body := `{"endpoint_id":"lt","presence":"intermittent","reason":"in use, often shut"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/presence", bytes.NewBufferString(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	if w := serveApproved(t, srv, srv.Handler(), req, body); w.Code != http.StatusOK {
		t.Fatalf("approved intermittent = %d %s", w.Code, w.Body.String())
	}
	ep, err := store.GetEndpoint("lt")
	if err != nil || ep.Presence != storage.PresenceIntermittent {
		t.Fatalf("presence = %+v %v", ep, err)
	}
	if w := postPresence(srv, "mock_admin_token", `{"endpoint_id":"lt","presence":"always_on"}`); w.Code != http.StatusOK {
		t.Fatalf("returning a host to always on needs no reason: %d %s", w.Code, w.Body.String())
	}
}

func TestNightshiftFeedHonoursPresence(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	for _, ep := range []storage.Endpoint{
		{ID: "srv", TenantID: "t-01", Hostname: "srv", RoleTag: "server", Status: "online", LastSeenAt: now},
		{ID: "laptop", TenantID: "t-01", Hostname: "laptop", RoleTag: "workstation", Status: "offline", LastSeenAt: now.Add(-20 * 24 * time.Hour)},
		{ID: "guest", TenantID: "t-01", Hostname: "guest", RoleTag: "workstation", Status: "offline", LastSeenAt: now.Add(-60 * 24 * time.Hour)},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatal(err)
		}
	}
	agents := func() (status int, message string, resources int) {
		t.Helper()
		var doc feedDoc
		w := feedRequest(srv, http.MethodGet, "/api/v1/integrations/nightshift/findings", "mock_admin_token")
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		for _, f := range doc.Findings {
			if f.FindingInfo.UID == "ominull.agents.offline" {
				return f.StatusID, f.Message, len(f.Resources)
			}
		}
		t.Fatal("no agents finding")
		return 0, "", 0
	}
	if status, msg, n := agents(); status != ocsfStatusNew || n != 2 {
		t.Fatalf("before presence: %d %q %d", status, msg, n)
	}
	if err := store.SetEndpointPresence("laptop", storage.PresenceIntermittent); err != nil {
		t.Fatal(err)
	}
	if err := store.SetEndpointPresence("guest", storage.PresenceParked); err != nil {
		t.Fatal(err)
	}
	if status, msg, _ := agents(); status != ocsfStatusResolved || !strings.Contains(msg, "1 parked endpoint is not watched") {
		t.Fatalf("after presence: %d %q", status, msg)
	}
}

// The console's verdict control reads the verdict back from the alert list.
func TestAlertListCarriesTheOperatorVerdict(t *testing.T) {
	t.Parallel()
	srv, store := setupTestServer(t)
	defer store.Close()
	now := time.Now().UTC()
	for _, id := range []string{"judged", "open"} {
		if err := store.CreateAnomalyAlert(storage.AnomalyAlert{ID: id, TenantID: "t-01", EndpointID: "e", Hostname: "e",
			AnomalyType: "NOVEL_DESTINATION", Severity: "MEDIUM", Title: id, Timestamp: now}); err != nil {
			t.Fatal(err)
		}
	}
	if w := replayRequest(srv, http.MethodPost, "/api/v1/anomalies/resolve", "mock_admin_token",
		map[string]any{"ids": []string{"judged"}, "verdict": "malicious", "reason": "owner confirmed"}); w.Code != http.StatusOK {
		t.Fatalf("resolve = %d %s", w.Code, w.Body.String())
	}
	w := replayRequest(srv, http.MethodGet, "/api/v1/anomalies?limit=10", "mock_admin_token", nil)
	var page struct {
		Alerts []storage.AnomalyAlert `json:"alerts"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Alerts) != 2 {
		t.Fatalf("alerts = %d %s %v", w.Code, w.Body.String(), err)
	}
	for _, a := range page.Alerts {
		switch {
		case a.ID == "judged" && (a.Resolution == nil || a.Resolution.Verdict != "malicious" || a.Resolution.Reason != "owner confirmed" || a.Resolution.Method != "operator"):
			t.Fatalf("judged alert resolution = %+v", a.Resolution)
		case a.ID == "open" && a.Resolution != nil:
			t.Fatalf("open alert has a resolution: %+v", a.Resolution)
		}
	}
}
