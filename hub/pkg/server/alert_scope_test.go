package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"ominull/hub/pkg/storage"
	"testing"
	"time"
)

func TestAlertSearchAppliesBeforePaginationAndToSummary(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, a := range []storage.AnomalyAlert{
		{ID: "older-match", EndpointID: "host-a", Hostname: "host-a", Title: "needle finding", Severity: "HIGH", Timestamp: time.Now().Add(-time.Hour)},
		{ID: "newer-other", EndpointID: "host-b", Hostname: "host-b", Title: "other finding", Severity: "HIGH", Timestamp: time.Now()},
	} {
		if err := store.CreateAnomalyAlert(a); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/anomalies?limit=1&search=needle", nil)
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("route: %d %s", w.Code, w.Body.String())
	}
	var result struct {
		Alerts    []storage.AnomalyAlert      `json:"alerts"`
		Total     int                         `json:"total"`
		Breakdown []storage.AnomalyAlertGroup `json:"breakdown"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || len(result.Alerts) != 1 || result.Alerts[0].ID != "older-match" {
		t.Errorf("search/page mismatch: %+v", result)
	}
	if len(result.Breakdown) != 1 || result.Breakdown[0].EndpointID != "host-a" || result.Breakdown[0].Total != 1 {
		t.Errorf("summary scope: %+v", result.Breakdown)
	}
}

func TestAssetAlertScopeUsesRecordedSourceIdentity(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()
	for _, a := range []storage.AnomalyAlert{
		{ID: "source", TenantID: "t-01", Evidence: `{"source_asset_id":"fixture-asset"}`, Timestamp: time.Now()},
		{ID: "destination-only", TenantID: "t-01", DstIP: "10.0.0.9", Evidence: `{}`, Timestamp: time.Now()},
		{ID: "other-source", TenantID: "t-01", Evidence: `{"source_asset_id":"other"}`, Timestamp: time.Now()},
		{ID: "legacy-invalid", TenantID: "t-01", Evidence: `legacy text`, Timestamp: time.Now()},
	} {
		if err := store.CreateAnomalyAlert(a); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest("GET", "/api/v1/anomalies?asset_id=fixture-asset", nil)
	r.Header.Set("X-API-Key", "mock_tenant_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	var result struct {
		Alerts []storage.AnomalyAlert
		Total  int
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || result.Total != 1 || len(result.Alerts) != 1 || result.Alerts[0].ID != "source" {
		t.Fatalf("incorrect source attribution: %d %+v", w.Code, result)
	}
}
