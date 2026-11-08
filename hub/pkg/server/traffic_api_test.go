package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestTrafficAPIEndpoints(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "traffic_api_test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New() failed: %v", err)
	}
	defer store.Close()

	srv := newTestServer(t, store, "mock_admin_token", tmpDir, "http://localhost:9999", "1.8.1")

	now := time.Now().UTC()
	events := []storage.Event{
		{
			Timestamp:   now.Add(-5 * time.Minute),
			EndpointID:  "ep-api-01",
			Layer:       "c-agent-raw",
			Action:      "PERMIT",
			Direction:   "OUTBOUND",
			Protocol:    6,
			SrcIP:       "10.0.0.10",
			DstIP:       "1.1.1.1",
			SrcPort:     50000,
			DstPort:     443,
			ProcessPath: "/usr/bin/curl",
			Domain:      "cloudflare.com",
			Country:     "US",
			BytesIn:     1000,
			BytesOut:    200,
		},
	}
	if err := store.InsertEventsBatch(events); err != nil {
		t.Fatalf("InsertEventsBatch failed: %v", err)
	}

	// 1. GET /api/v1/traffic/overview
	reqOverview := httptest.NewRequest(http.MethodGet, "/api/v1/traffic/overview?range=1h", nil)
	reqOverview.Header.Set("X-API-Key", "mock_admin_token")
	wOverview := httptest.NewRecorder()
	srv.authMiddleware(srv.handleTrafficOverview).ServeHTTP(wOverview, reqOverview)

	if wOverview.Code != http.StatusOK {
		t.Fatalf("handleTrafficOverview returned code %d, want 200: %s", wOverview.Code, wOverview.Body.String())
	}
	var ovRes storage.TrafficOverview
	if err := json.Unmarshal(wOverview.Body.Bytes(), &ovRes); err != nil {
		t.Fatalf("unmarshal overview failed: %v", err)
	}
	if ovRes.TotalFlows != 1 {
		t.Errorf("expected 1 total flow, got %d", ovRes.TotalFlows)
	}
	if ovRes.Totals.TotalBytes != 1200 {
		t.Errorf("expected 1200 total bytes, got %d", ovRes.Totals.TotalBytes)
	}

	// 2. GET /api/v1/traffic/flows
	reqFlows := httptest.NewRequest(http.MethodGet, "/api/v1/traffic/flows?range=1h", nil)
	reqFlows.Header.Set("X-API-Key", "mock_admin_token")
	wFlows := httptest.NewRecorder()
	srv.authMiddleware(srv.handleTrafficFlows).ServeHTTP(wFlows, reqFlows)

	if wFlows.Code != http.StatusOK {
		t.Fatalf("handleTrafficFlows returned code %d, want 200", wFlows.Code)
	}
	var flowsRes storage.TrafficFlowsResult
	if err := json.Unmarshal(wFlows.Body.Bytes(), &flowsRes); err != nil {
		t.Fatalf("unmarshal flows failed: %v", err)
	}
	if len(flowsRes.Flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flowsRes.Flows))
	}

}

// The conversations route answers in the storage shape and refuses an unknown
// mark or direction instead of silently showing everything.
func TestTrafficConversationsAPI(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	store, err := storage.New(filepath.Join(tmpDir, "conversations_api.db"))
	if err != nil {
		t.Fatalf("storage.New() failed: %v", err)
	}
	defer store.Close()
	srv := newTestServer(t, store, "mock_admin_token", tmpDir, "http://localhost:9999", "1.8.1")
	now := time.Now().UTC()
	if err := store.InsertEventsBatch([]storage.Event{{
		Timestamp: now.Add(-5 * time.Minute), EndpointID: "ep-api-01", Layer: "test", Action: "PERMIT", Direction: "OUTBOUND",
		Protocol: 6, SrcIP: "10.0.0.10", DstIP: "192.0.2.1", SrcPort: 50000, DstPort: 443, ProcessPath: "/usr/bin/curl",
	}}); err != nil {
		t.Fatalf("InsertEventsBatch failed: %v", err)
	}
	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		srv.authMiddleware(srv.handleTrafficConversations).ServeHTTP(w, req)
		return w
	}
	w := get("/api/v1/traffic/conversations?range=1h")
	if w.Code != http.StatusOK {
		t.Fatalf("conversations: %d %s", w.Code, w.Body.String())
	}
	var res storage.TrafficConversations
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(res.Conversations) != 1 || res.Conversations[0].Port != 443 || res.Conversations[0].Process != "curl" || res.Counts.All != 1 {
		t.Fatalf("one curl conversation on 443: %+v", res)
	}
	for _, bad := range []string{"mark=everything", "dir=sideways"} {
		if w := get("/api/v1/traffic/conversations?range=1h&" + bad); w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", bad, w.Code)
		}
	}
}
