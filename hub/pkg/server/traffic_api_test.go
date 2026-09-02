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
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "traffic_api_test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New() failed: %v", err)
	}
	defer store.Close()

	srv := New(store, "mock_admin_token", tmpDir, "http://localhost:9999", "1.8.1")

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

	// 3. GET /api/v1/traffic/flows/{id}
	flowID := flowsRes.Flows[0].ID
	reqSingle := httptest.NewRequest(http.MethodGet, "/api/v1/traffic/flows/"+flowID, nil)
	reqSingle.Header.Set("X-API-Key", "mock_admin_token")
	wSingle := httptest.NewRecorder()
	srv.authMiddleware(srv.handleTrafficFlows).ServeHTTP(wSingle, reqSingle)

	if wSingle.Code != http.StatusOK {
		t.Fatalf("handleTrafficFlowDetail returned code %d, want 200", wSingle.Code)
	}
	var singleFlow storage.TrafficFlowItem
	if err := json.Unmarshal(wSingle.Body.Bytes(), &singleFlow); err != nil {
		t.Fatalf("unmarshal single flow failed: %v", err)
	}
	if singleFlow.ID != flowID || singleFlow.EndpointID != "ep-api-01" {
		t.Errorf("unexpected single flow: %+v", singleFlow)
	}
}
