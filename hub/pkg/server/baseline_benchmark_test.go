package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func BenchmarkHeartbeatIngestion(b *testing.B) {
	srv, store := setupTestServerBench(b)
	defer store.Close()

	batch := TelemetryBatchMessage{
		Type:                     "telemetry",
		EndpointID:               "bench-ep-01",
		TenantID:                 "t-01",
		Hostname:                 "bench-node",
		OS:                       "linux",
		IP:                       "10.0.0.101",
		MAC:                      "52:54:00:12:34:56",
		DriverVersion:            "1.8.3",
		RegisteredPackageVersion: "1.8.3",
		Events: []storage.Event{
			{
				TenantID:    "t-01",
				EndpointID:  "bench-ep-01",
				Timestamp:   time.Now().UTC(),
				Layer:       "FLOW",
				Action:      "PERMIT",
				Direction:   "OUTBOUND",
				Protocol:    6,
				SrcIP:       "10.0.0.101",
				DstIP:       "10.0.0.1",
				SrcPort:     50000,
				DstPort:     443,
				BytesIn:     1024,
				BytesOut:    512,
				ProcessPath: "/usr/bin/curl",
				ProcessID:   1234,
			},
		},
	}
	reqBody, _ := json.Marshal(batch)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()

		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
		}
	}
}

func BenchmarkSQLiteEventBatchInsert(b *testing.B) {
	_, store := setupTestServerBench(b)
	defer store.Close()

	batch := make([]storage.Event, 50)
	now := time.Now().UTC()
	for i := range batch {
		batch[i] = storage.Event{
			TenantID:    "t-01",
			EndpointID:  "bench-ep-01",
			Timestamp:   now,
			Layer:       "FLOW",
			Action:      "PERMIT",
			Direction:   "OUTBOUND",
			Protocol:    6,
			SrcIP:       "10.0.0.101",
			DstIP:       "10.0.0.1",
			SrcPort:     uint16(50000 + i),
			DstPort:     443,
			BytesIn:     1024,
			BytesOut:    512,
			ProcessPath: "/usr/bin/curl",
			ProcessID:   uint32(1000 + i),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := store.InsertEventsBatch(batch); err != nil {
			b.Fatalf("InsertEventsBatch failed: %v", err)
		}
	}
}

func BenchmarkResponseGateFailClosed(b *testing.B) {
	srv, store := setupTestServerBench(b)
	defer store.Close()

	reqBody := []byte(`{"job_id":"job-test","kind":"forensic_collection"}`)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/response/jobs", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()

		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			b.Fatalf("expected 404 Not Found, got %d", w.Code)
		}
	}
}

func setupTestServerBench(b *testing.B) (*Server, *storage.Store) {
	tempDir := b.TempDir()
	store, err := storage.New(filepath.Join(tempDir, "bench.db"))
	if err != nil {
		b.Fatalf("Storage init failed: %v", err)
	}

	store.CreateTenant(storage.Tenant{
		ID:        "t-01",
		Name:      "Bench Tenant",
		APIKey:    "mock_tenant_token",
		CreatedAt: time.Now().UTC(),
	})
	_ = store.SetSetting("legacy_agent_auth", "migration")

	_ = store.UpsertEndpoint(storage.Endpoint{
		ID:         "bench-ep-01",
		TenantID:   "t-01",
		Hostname:   "bench-node",
		IP:         "10.0.0.101",
		MAC:        "52:54:00:12:34:56",
		OS:                       "linux",
		RegisteredPackageVersion: "1.8.3",
		Status:                   "online",
		LastSeenAt: time.Now().UTC(),
	})

	srv := New(store, "mock_admin_token", tempDir, "http://10.0.0.57:9999", "1.8.3")
	return srv, store
}
