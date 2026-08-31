package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestRetiringEndpointPreservesHistoryAndLeavesFleetConverged(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	now := time.Now().UTC()
	ep := storage.Endpoint{
		ID: "retired-macos", TenantID: "default", Hostname: "retired-macos",
		OS: "macOS", IP: "10.0.4.44", DriverVersion: "1.0.0",
		UpdateCapability: "", Status: "online", IsIsolated: true,
		LastSeenAt: now, CreatedAt: now,
	}
	if err := store.UpsertEndpoint(ep); err != nil {
		t.Fatalf("upsert endpoint: %v", err)
	}
	if err := store.SetEndpointIsolation(ep.ID, true, []string{"10.0.0.1"}); err != nil {
		t.Fatalf("set isolation: %v", err)
	}
	if err := store.RequestAgentUpdate(ep.ID, "1.1.0"); err != nil {
		t.Fatalf("queue update: %v", err)
	}
	if err := store.InsertEvent(storage.Event{
		TenantID: "default", EndpointID: ep.ID, Timestamp: now,
		Layer: "linux-socket-v1", Action: "PERMIT", Direction: "OUTBOUND",
		Protocol: 6, SrcIP: ep.IP, DstIP: "10.0.0.8", DstPort: 443,
		Country: "US", ProcessPath: "/usr/bin/curl",
	}); err != nil {
		t.Fatalf("insert history: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints/retire",
		bytes.NewBufferString(`{"endpoint_id":"retired-macos","reason":"platform retired"}`))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("retire returned %d: %s", w.Code, w.Body.String())
	}

	got, err := store.GetEndpoint(ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Status != "retired" || got.IsIsolated {
		t.Fatalf("retirement did not clear live control state: %+v", got)
	}
	if isolated, allow, err := store.GetEndpointIsolation(ep.ID); err != nil || isolated || len(allow) != 0 {
		t.Fatalf("retirement left isolation state: isolated=%v allow=%v err=%v", isolated, allow, err)
	}
	if pending, err := store.ListPendingAgentUpdates(); err != nil || len(pending) != 0 {
		t.Fatalf("retirement left a pending update: %v (%v)", pending, err)
	}
	if events, err := store.ListEvents("default", 10); err != nil || len(events) != 1 || events[0].EndpointID != ep.ID {
		t.Fatalf("retirement removed telemetry history: %v (%v)", events, err)
	}
	logs, err := store.ListAuditLogs("", 20)
	if err != nil || len(logs) == 0 || logs[0].Action != "ENDPOINT_RETIRED" {
		t.Fatalf("retirement was not audited: %v (%v)", logs, err)
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/agents/update-status", nil)
	statusReq.Header.Set("X-API-Key", "mock_admin_token")
	statusW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(statusW, statusReq)
	var status struct {
		NativeConverged bool                     `json:"native_converged"`
		Retired         []map[string]interface{} `json:"retired"`
	}
	if statusW.Code != http.StatusOK || json.NewDecoder(statusW.Body).Decode(&status) != nil {
		t.Fatalf("update status failed: %d %s", statusW.Code, statusW.Body.String())
	}
	if !status.NativeConverged || len(status.Retired) != 1 {
		t.Fatalf("retired endpoint blocked convergence: %+v", status)
	}

	// A late heartbeat must not silently revive a deliberately retired row.
	heartbeat, _ := json.Marshal(TelemetryBatchMessage{
		Type: "telemetry", EndpointID: ep.ID, Hostname: ep.Hostname,
		OS: ep.OS, IP: ep.IP, DriverVersion: "1.1.0", Events: []storage.Event{},
	})
	heartbeatReq := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(heartbeat))
	heartbeatReq.Header.Set("X-API-Key", "mock_admin_token")
	heartbeatW := httptest.NewRecorder()
	srv.Handler().ServeHTTP(heartbeatW, heartbeatReq)
	if heartbeatW.Code != http.StatusGone {
		t.Fatalf("late retired heartbeat returned %d: %s", heartbeatW.Code, heartbeatW.Body.String())
	}
	got, err = store.GetEndpoint(ep.ID)
	if err != nil || got == nil || got.Status != "retired" {
		t.Fatalf("late heartbeat revived endpoint: %+v (%v)", got, err)
	}
}

func TestNativeProvenanceRoundTripAndStatusGate(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	now := time.Now().UTC()
	for _, ep := range []storage.Endpoint{
		{
			ID:                       "linux-native",
			TenantID:                 "default",
			Hostname:                 "linux-native",
			OS:                       "Linux 6.8",
			IP:                       "10.0.4.31",
			DriverVersion:            "1.1.0",
			UpdateCapability:         "deb",
			InstallType:              "deb",
			PackageIdentifier:        linuxAgentPackageID,
			RegisteredPackageVersion: "1.1.0",
			ProvenanceStatus:         "native",
			Status:                   "online",
			LastSeenAt:               now,
			CreatedAt:                now,
		},
		{
			ID:                       "windows-manual",
			TenantID:                 "default",
			Hostname:                 "windows-manual",
			OS:                       "Windows 11",
			IP:                       "10.0.4.32",
			DriverVersion:            "1.1.0",
			UpdateCapability:         "msi",
			InstallType:              "manual",
			PackageIdentifier:        "legacy-archive",
			RegisteredPackageVersion: "",
			ProvenanceStatus:         "manual",
			Status:                   "online",
			LastSeenAt:               now,
			CreatedAt:                now,
		},
	} {
		if err := store.UpsertEndpoint(ep); err != nil {
			t.Fatalf("upsert %s: %v", ep.ID, err)
		}
	}

	got, err := store.GetEndpoint("linux-native")
	if err != nil {
		t.Fatal(err)
	}
	if got.InstallType != "deb" || got.PackageIdentifier != linuxAgentPackageID || got.RegisteredPackageVersion != "1.1.0" || got.ProvenanceStatus != "native" {
		t.Fatalf("native provenance did not round-trip: %+v", got)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/update-status", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentsUpdateStatus)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status returned %d: %s", w.Code, w.Body.String())
	}
	var status struct {
		NativeConverged  bool                     `json:"native_converged"`
		ProvenanceIssues []map[string]interface{} `json:"provenance_issues"`
	}
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.NativeConverged || len(status.ProvenanceIssues) != 1 {
		t.Fatalf("manual endpoint must block native convergence: %+v", status)
	}
	if status.ProvenanceIssues[0]["endpoint_id"] != "windows-manual" {
		t.Fatalf("wrong provenance issue: %+v", status.ProvenanceIssues)
	}
}
