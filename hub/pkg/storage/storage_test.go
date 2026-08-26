package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStorageLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_ominull.db")

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()

	// 1. Tenant Creation & Lookup
	tenant := Tenant{
		ID:        "tenant-mssp-01",
		Name:      "Acme Cyber Defense",
		APIKey:    "dummy_mock_key_01",
		CreatedAt: time.Now().UTC(),
	}

	if err := store.CreateTenant(tenant); err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}

	found, err := store.GetTenantByAPIKey("dummy_mock_key_01")
	if err != nil || found == nil {
		t.Fatalf("GetTenantByAPIKey failed: %v", err)
	}
	if found.Name != "Acme Cyber Defense" {
		t.Errorf("Expected tenant name 'Acme Cyber Defense', got '%s'", found.Name)
	}

	// 2. Endpoint Registration
	ep := Endpoint{
		ID:            "ep-win11-01",
		TenantID:      tenant.ID,
		Hostname:      "DESKTOP-IR01",
		OS:            "Windows 11 Enterprise",
		IP:            "10.0.0.110",
		DriverVersion: "1.0.0",
		Status:        "online",
		IsIsolated:    false,
		LastSeenAt:    time.Now().UTC(),
		CreatedAt:     time.Now().UTC(),
	}

	if err := store.UpsertEndpoint(ep); err != nil {
		t.Fatalf("UpsertEndpoint failed: %v", err)
	}

	endpoints, err := store.ListEndpoints(tenant.ID)
	if err != nil || len(endpoints) != 1 {
		t.Fatalf("ListEndpoints failed: len=%d, err=%v", len(endpoints), err)
	}

	// 3. Events Ingestion & Query
	events := []Event{
		{
			TenantID:    tenant.ID,
			EndpointID:  ep.ID,
			Timestamp:   time.Now().UTC(),
			Layer:       "CONNECT_V4",
			Action:      "PERMIT",
			Direction:   "OUTBOUND",
			Protocol:    6,
			SrcIP:       "10.0.0.110",
			DstIP:       "1.1.1.1",
			SrcPort:     49152,
			DstPort:     443,
			ProcessPath: "C:\\Windows\\System32\\svchost.exe",
			ProcessID:   1120,
		},
		{
			TenantID:    tenant.ID,
			EndpointID:  ep.ID,
			Timestamp:   time.Now().UTC(),
			Layer:       "CONNECT_V4",
			Action:      "BLOCK",
			Direction:   "OUTBOUND",
			Protocol:    6,
			SrcIP:       "10.0.0.110",
			DstIP:       "198.51.100.25",
			SrcPort:     49153,
			DstPort:     8080,
			ProcessPath: "C:\\Users\\Analyst\\AppData\\Local\\Temp\\malware.exe",
			ProcessID:   4488,
		},
	}

	if err := store.InsertEventsBatch(events); err != nil {
		t.Fatalf("InsertEventsBatch failed: %v", err)
	}

	queried, err := store.QueryEvents(tenant.ID, ep.ID, 10)
	if err != nil || len(queried) != 2 {
		t.Fatalf("QueryEvents failed: len=%d, err=%v", len(queried), err)
	}

	if queried[0].Action != "BLOCK" && queried[1].Action != "BLOCK" {
		t.Errorf("Expected blocked event in query results")
	}

	// 4. Host Isolation State Toggle
	if err := store.SetEndpointIsolation(ep.ID, true); err != nil {
		t.Fatalf("SetEndpointIsolation failed: %v", err)
	}

	endpoints, _ = store.ListEndpoints(tenant.ID)
	if !endpoints[0].IsIsolated {
		t.Errorf("Expected endpoint to be isolated")
	}
}

func init() {
	// Suppress unneeded warnings
	os.Setenv("SQLITE_TMPDIR", os.TempDir())
}
