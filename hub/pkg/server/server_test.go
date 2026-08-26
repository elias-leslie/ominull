package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func setupTestServer(t *testing.T) (*Server, *storage.Store) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("Storage init failed: %v", err)
	}

	// Create test tenant
	store.CreateTenant(storage.Tenant{
		ID:        "t-01",
		Name:      "Test Tenant",
		APIKey:    "mock_tenant_token",
		CreatedAt: time.Now().UTC(),
	})

	srv := New(store, "mock_admin_token", tempDir, "http://10.0.0.57:9999")
	return srv, store
}

func TestBootstrapGenerators(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	// 1. PowerShell Bootstrap
	req := httptest.NewRequest("GET", "/bootstrap.ps1?key=mock_tenant_token", nil)
	w := httptest.NewRecorder()
	srv.handleBootstrapPS1(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Ominull Threat Nullification Service") || !strings.Contains(body, "mock_tenant_token") {
		t.Errorf("PowerShell script missing expected bootstrap instructions: %s", body)
	}

	// 2. Bash Bootstrap
	req = httptest.NewRequest("GET", "/bootstrap.sh?key=mock_tenant_token", nil)
	w = httptest.NewRecorder()
	srv.handleBootstrapSH(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	body = w.Body.String()
	if !strings.Contains(body, "ominulld.service") || !strings.Contains(body, "mock_tenant_token") {
		t.Errorf("Bash script missing expected systemd service configuration: %s", body)
	}
}

func TestMultiTenantAPIAuth(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	// 1. Unauthorized request (No API Key)
	req := httptest.NewRequest("GET", "/api/v1/endpoints", nil)
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleEndpoints)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for missing API key, got %d", w.Code)
	}

	// 2. Admin Request
	req = httptest.NewRequest("GET", "/api/v1/endpoints", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleEndpoints)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for admin API key, got %d", w.Code)
	}

	// 3. Ingesting Telemetry Events via Tenant Key
	eventPayload := []storage.Event{
		{
			Layer:       "CONNECT_V4",
			Action:      "BLOCK",
			Direction:   "OUTBOUND",
			Protocol:    6,
			SrcIP:       "10.0.0.5",
			DstIP:       "203.0.113.55",
			SrcPort:     12345,
			DstPort:     443,
			ProcessPath: "C:\\Windows\\System32\\cmd.exe",
			ProcessID:   999,
		},
	}
	data, _ := json.Marshal(eventPayload)

	req = httptest.NewRequest("POST", "/api/v1/events", bytes.NewReader(data))
	req.Header.Set("X-API-Key", "mock_tenant_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		tenantID := r.Header.Get("X-Tenant-ID")
		var evs []storage.Event
		json.NewDecoder(r.Body).Decode(&evs)
		for i := range evs {
			evs[i].TenantID = tenantID
			evs[i].EndpointID = "ep-test"
			evs[i].Timestamp = time.Now().UTC()
		}
		store.InsertEventsBatch(evs)
		w.WriteHeader(http.StatusOK)
	})(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for event insertion, got %d", w.Code)
	}

	// 4. Query Events
	req = httptest.NewRequest("GET", "/api/v1/events", nil)
	req.Header.Set("X-API-Key", "mock_tenant_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleEvents)(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for querying events, got %d", w.Code)
	}

	var results []storage.Event
	json.NewDecoder(w.Body).Decode(&results)
	if len(results) != 1 || results[0].Action != "BLOCK" {
		t.Errorf("Expected 1 blocked event, got %v", results)
	}
}
