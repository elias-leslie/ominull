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

func TestServer_LineageAndHashing_IngestionAndAPI(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "lineage_api_test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New() failed: %v", err)
	}
	defer store.Close()

	adminKey := "mock_admin_key_lineage"
	srv := New(store, adminKey, tmpDir, "http://localhost:9999", "1.8.3")

	now := time.Now().UTC().Truncate(time.Millisecond)
	observed := now.Add(-300 * time.Millisecond)

	// Register endpoint and device credential so endpoint can send telemetry
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID:         "ep-lineage-01",
		TenantID:   "default",
		Hostname:   "linux-lineage-host",
		OS:         "Linux 6.17",
		IP:         "10.0.0.62",
		Status:     "online",
		LastSeenAt: now,
		CreatedAt:  now,
	}); err != nil {
		t.Fatalf("UpsertEndpoint failed: %v", err)
	}

	deviceKey, _, err := store.IssueDeviceCredential("ep-lineage-01")
	if err != nil {
		t.Fatalf("IssueDeviceCredential failed: %v", err)
	}

	// 1. Post telemetry batch with enriched process lineage and executable hash fields
	telemetryBody := map[string]interface{}{
		"type":        "telemetry",
		"endpoint_id": "ep-lineage-01",
		"tenant_id":   "default",
		"hostname":    "linux-lineage-host",
		"os":          "Linux 6.17",
		"ip":          "10.0.0.62",
		"mac":         "00:11:22:33:44:55",
		"events": []map[string]interface{}{
			{
				"layer":                      "linux-socket-v1",
				"action":                     "PERMIT",
				"direction":                  "OUTBOUND",
				"protocol":                   6,
				"src_ip":                     "10.0.0.62",
				"dst_ip":                     "93.184.216.34",
				"src_port":                   42100,
				"dst_port":                   443,
				"bytes_in":                   2048,
				"bytes_out":                  512,
				"process_path":               "/usr/bin/curl",
				"process_id":                 9876,
				"domain":                     "example.invalid",
				"process_instance_id":        "boot-a1b2c3:9876:1788543000",
				"parent_pid":                 4321,
				"parent_process_instance_id": "boot-a1b2c3:4321:1788542000",
				"command_line":               "/usr/bin/curl -v https://example.invalid",
				"user_identity":              "developer",
				"executable_sha256":          "ea8f5a11c080b0800b46296766d0c242013f9ae05b1de1efc6fc525ad21c0836",
				"attribution_status":         "authoritative",
				"observed_at":                observed.Format(time.RFC3339Nano),
			},
			{
				// Legacy event without enrichment fields in the same batch
				"layer":        "linux-socket-v1",
				"action":       "PERMIT",
				"direction":    "OUTBOUND",
				"protocol":     17,
				"src_ip":       "10.0.0.62",
				"dst_ip":       "1.1.1.1",
				"src_port":     53535,
				"dst_port":     53,
				"bytes_in":     120,
				"bytes_out":    60,
				"process_path": "/usr/lib/systemd/systemd-resolved",
				"process_id":   102,
			},
		},
	}

	bodyBytes, _ := json.Marshal(telemetryBody)
	reqTel := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(bodyBytes))
	reqTel.Header.Set("Content-Type", "application/json")
	reqTel.Header.Set("X-API-Key", deviceKey)
	wTel := httptest.NewRecorder()
	srv.handleEvents(wTel, reqTel)

	if wTel.Code != http.StatusOK {
		t.Fatalf("handleEvents returned code %d, want 200: %s", wTel.Code, wTel.Body.String())
	}

	// 2. Query /api/v1/events?endpoint_id=ep-lineage-01
	reqEv := httptest.NewRequest(http.MethodGet, "/api/v1/events?endpoint_id=ep-lineage-01", nil)
	reqEv.Header.Set("X-API-Key", adminKey)
	wEv := httptest.NewRecorder()
	srv.authMiddleware(srv.handleEvents).ServeHTTP(wEv, reqEv)

	if wEv.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/events returned code %d, want 200: %s", wEv.Code, wEv.Body.String())
	}

	var events []storage.Event
	if err := json.Unmarshal(wEv.Body.Bytes(), &events); err != nil {
		t.Fatalf("unmarshal events failed: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	// Find the curl event
	var curlEvent *storage.Event
	for i := range events {
		if events[i].ProcessPath == "/usr/bin/curl" {
			curlEvent = &events[i]
			break
		}
	}
	if curlEvent == nil {
		t.Fatalf("curl event not found in /api/v1/events response")
	}

	if curlEvent.ProcessInstanceID != "boot-a1b2c3:9876:1788543000" {
		t.Errorf("ProcessInstanceID mismatch: %q", curlEvent.ProcessInstanceID)
	}
	if curlEvent.ParentPID != 4321 {
		t.Errorf("ParentPID mismatch: %d", curlEvent.ParentPID)
	}
	if curlEvent.ParentProcessInstanceID != "boot-a1b2c3:4321:1788542000" {
		t.Errorf("ParentProcessInstanceID mismatch: %q", curlEvent.ParentProcessInstanceID)
	}
	if curlEvent.CommandLine != "/usr/bin/curl -v https://example.invalid" {
		t.Errorf("CommandLine mismatch: %q", curlEvent.CommandLine)
	}
	if curlEvent.UserIdentity != "developer" {
		t.Errorf("UserIdentity mismatch: %q", curlEvent.UserIdentity)
	}
	if curlEvent.ExecutableSHA256 != "ea8f5a11c080b0800b46296766d0c242013f9ae05b1de1efc6fc525ad21c0836" {
		t.Errorf("ExecutableSHA256 mismatch: %q", curlEvent.ExecutableSHA256)
	}
	if curlEvent.AttributionStatus != "authoritative" {
		t.Errorf("AttributionStatus mismatch: %q", curlEvent.AttributionStatus)
	}

	// 3. Query /api/v1/traffic/flows?endpoint_id=ep-lineage-01
	reqFlows := httptest.NewRequest(http.MethodGet, "/api/v1/traffic/flows?endpoint_id=ep-lineage-01", nil)
	reqFlows.Header.Set("X-API-Key", adminKey)
	wFlows := httptest.NewRecorder()
	srv.authMiddleware(srv.handleTrafficFlows).ServeHTTP(wFlows, reqFlows)

	if wFlows.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/traffic/flows returned code %d, want 200: %s", wFlows.Code, wFlows.Body.String())
	}

	var flowsResult storage.TrafficFlowsResult
	if err := json.Unmarshal(wFlows.Body.Bytes(), &flowsResult); err != nil {
		t.Fatalf("unmarshal flows failed: %v", err)
	}

	var flowItem *storage.TrafficFlowItem
	for i := range flowsResult.Flows {
		if flowsResult.Flows[i].ProcessPath == "/usr/bin/curl" {
			flowItem = &flowsResult.Flows[i]
			break
		}
	}
	if flowItem == nil {
		t.Fatalf("curl flow item not found in /api/v1/traffic/flows response")
	}

	if flowItem.CommandLine != "/usr/bin/curl -v https://example.invalid" {
		t.Errorf("flowItem.CommandLine mismatch: %q", flowItem.CommandLine)
	}
	if flowItem.ExecutableSHA256 != "ea8f5a11c080b0800b46296766d0c242013f9ae05b1de1efc6fc525ad21c0836" {
		t.Errorf("flowItem.ExecutableSHA256 mismatch: %q", flowItem.ExecutableSHA256)
	}
	if flowItem.AttributionStatus != "authoritative" {
		t.Errorf("flowItem.AttributionStatus mismatch: %q", flowItem.AttributionStatus)
	}

	// 4. Query /api/v1/traffic/flows/<flow_id>
	reqDetail := httptest.NewRequest(http.MethodGet, "/api/v1/traffic/flows/"+flowItem.ID, nil)
	reqDetail.Header.Set("X-API-Key", adminKey)
	wDetail := httptest.NewRecorder()
	srv.authMiddleware(srv.handleTrafficFlows).ServeHTTP(wDetail, reqDetail)

	if wDetail.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/traffic/flows/<id> returned code %d, want 200: %s", wDetail.Code, wDetail.Body.String())
	}

	var singleDetail storage.TrafficFlowItem
	if err := json.Unmarshal(wDetail.Body.Bytes(), &singleDetail); err != nil {
		t.Fatalf("unmarshal single flow detail failed: %v", err)
	}
	if singleDetail.CommandLine != flowItem.CommandLine {
		t.Errorf("singleDetail.CommandLine mismatch: %q", singleDetail.CommandLine)
	}
	if singleDetail.ProcessInstanceID != flowItem.ProcessInstanceID {
		t.Errorf("singleDetail.ProcessInstanceID mismatch: %q", singleDetail.ProcessInstanceID)
	}
}
