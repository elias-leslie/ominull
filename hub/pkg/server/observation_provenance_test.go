package server

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTelemetryRetainsObservationBasisTimingAndCollectorHealth(t *testing.T) {
	s, db := setupTestServer(t)
	defer db.Close()
	at := time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	body := fmt.Sprintf(`{"type":"telemetry","endpoint_id":"udp-observer","ip":"10.0.4.20","collector_health":[{"name":"linux-bpf-udp","state":"active","dropped":3,"queued":4,"scope_omitted":2,"schema_omitted":1,"buffers_lost":2}],"events":[{"timestamp":%q,"protocol":17,"src_ip":"10.0.4.20","dst_ip":"10.0.4.21","dst_port":9000,"process_id":321,"bytes_out":10,"observation":{"source":"linux-bpf-udp","byte_basis":"udp_payload","count":2,"first_at":%q,"last_at":%q}}]}`, at, at, at)
	r := httptest.NewRequest("POST", "/api/v1/events", strings.NewReader(body))
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("ingestion: %d %s", w.Code, w.Body.String())
	}
	events, err := db.ListEvents("default", 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events: %v %v", events, err)
	}
	raw, _ := json.Marshal(events[0])
	var event map[string]any
	_ = json.Unmarshal(raw, &event)
	obs, ok := event["observation"].(map[string]any)
	if !ok || obs["byte_basis"] != "udp_payload" || obs["count"] != float64(2) || obs["first_at"] != at || obs["last_at"] != at || obs["lost"] != float64(1) || obs["incomplete"] != true {
		t.Errorf("lost observation provenance: %s", raw)
	}

	r = httptest.NewRequest("GET", "/api/v1/traffic/flows?endpoint_id=udp-observer", nil)
	r.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	var result struct {
		Flows []map[string]any `json:"flows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || len(result.Flows) != 1 {
		t.Fatalf("flow route: %s %v", w.Body.String(), err)
	}
	if result.Flows[0]["observation"] == nil || result.Flows[0]["process_id"] != float64(321) {
		t.Errorf("flow inspector lost observation or PID: %v", result.Flows[0])
	}
	ep, err := db.GetEndpoint("udp-observer")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(ep)
	var endpoint map[string]any
	_ = json.Unmarshal(raw, &endpoint)
	health, ok := endpoint["collector_health"].([]any)
	if !ok || len(health) != 1 {
		t.Fatalf("lost collector health: %s", raw)
	}
	h := health[0].(map[string]any)
	if h["dropped"] != float64(3) || h["queued"] != float64(4) || h["scope_omitted"] != float64(2) || h["schema_omitted"] != float64(1) || h["buffers_lost"] != float64(2) {
		t.Fatalf("health counters changed: %v", h)
	}
}

func TestInvalidObservationWindowRejectsBatchBeforeEndpointWrite(t *testing.T) {
	s, db := setupTestServer(t)
	defer db.Close()
	r := httptest.NewRequest("POST", "/api/v1/events", strings.NewReader(`{"type":"telemetry","endpoint_id":"invalid-observer","events":[{"protocol":17,"observation":{"source":"linux-bpf-udp","byte_basis":"udp_payload","timing":"socket_io","count":1,"first_at":"2026-01-02T00:00:00Z","last_at":"2026-01-01T00:00:00Z"}}]}`))
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 400 {
		t.Errorf("invalid observation accepted: %d %s", w.Code, w.Body.String())
	}
	ep, err := db.GetEndpoint("invalid-observer")
	if err != nil || ep != nil {
		t.Fatalf("invalid batch wrote endpoint: %v %v", ep, err)
	}
}

func TestLegacyTelemetryPreservesPerEventEndpoint(t *testing.T) {
	s, db := setupTestServer(t)
	defer db.Close()
	r := httptest.NewRequest("POST", "/api/v1/events", strings.NewReader(`[{"endpoint_id":"legacy-observer","protocol":17,"src_ip":"10.0.4.20","dst_ip":"10.0.4.21","bytes_out":5}]`))
	r.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("legacy ingestion: %d %s", w.Code, w.Body.String())
	}
	events, err := db.ListEvents("default", 10)
	if err != nil || len(events) != 1 || events[0].EndpointID != "legacy-observer" {
		t.Fatalf("lost legacy endpoint: %+v %v", events, err)
	}
}
