package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
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

	srv := New(store, "mock_admin_token", tempDir, "http://10.0.0.57:9999", "1.1.0")
	return srv, store
}

func TestBootstrapGenerators(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	// 0. Bootstrap must never be minted without the admin key (no defaults, no tenant keys).
	for _, path := range []string{"/bootstrap.ps1", "/bootstrap.sh", "/bootstrap_mac.sh"} {
		for _, name := range []string{"no-key", "wrong-key"} {
			url := path
			if name == "wrong-key" {
				url = path + "?key=mock_tenant_token"
			}
			req := httptest.NewRequest("GET", url, nil)
			w := httptest.NewRecorder()
			switch path {
			case "/bootstrap.ps1":
				srv.handleBootstrapPS1(w, req)
			case "/bootstrap.sh":
				srv.handleBootstrapSH(w, req)
			default:
				srv.handleBootstrapMac(w, req)
			}
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s (%s): expected 401 Unauthorized, got %d", path, name, w.Code)
			}
		}
	}

	// 1. PowerShell Bootstrap (admin key required)
	req := httptest.NewRequest("GET", "/bootstrap.ps1?key=mock_admin_token", nil)
	w := httptest.NewRecorder()
	srv.handleBootstrapPS1(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Ominull Threat Nullification Service") || !strings.Contains(body, "mock_admin_token") {
		t.Errorf("PowerShell script missing expected bootstrap instructions: %s", body)
	}

	// 2. Bash Bootstrap (admin key required)
	req = httptest.NewRequest("GET", "/bootstrap.sh?key=mock_admin_token", nil)
	w = httptest.NewRecorder()
	srv.handleBootstrapSH(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}
	body = w.Body.String()
	if !strings.Contains(body, "ominulld.service") || !strings.Contains(body, "mock_admin_token") {
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

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.1.0", "1.1.0", 0},
		{"1.1.0", "1.2.0", -1},
		{"1.2.0", "1.1.0", 1},
		{"1.1.0", "1.1.1", -1},
		{"2.0.0", "1.9.9", 1},
		{"v1.1.0", "1.1.0", 0},
		// Endpoints decorate the version with their enforcement engine.
		{"1.1.0 (WFP Callout)", "1.1.0", 0},
		{"1.1.0 (eBPF/TC)", "1.2.0", -1},
		{"1.2.0 (PF)", "1.1.0 (eBPF/TC)", 1},
		// Short and empty forms fall back to zeroes rather than erroring.
		{"1.1", "1.1.0", 0},
		{"", "1.1.0", -1},
		{"1.1.0", "", 1},
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAgentPackageKind(t *testing.T) {
	cases := map[string]string{
		"Windows 11 Enterprise (x86_64)": "windows",
		"macOS Sonoma 14.8 (x86_64)":     "macos",
		"Darwin 23.6.0 (arm64)":          "macos",
		"Linux 6.8.0-40-generic":         "deb",
		"":                               "deb",
	}
	for osName, want := range cases {
		if got := agentPackageKind(osName); got != want {
			t.Errorf("agentPackageKind(%q) = %q, want %q", osName, got, want)
		}
	}
}

// seedEndpoint registers an endpoint reporting a specific agent version.
func seedEndpoint(t *testing.T, store *storage.Store, id, osName, version string) {
	t.Helper()
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID:            id,
		TenantID:      "default",
		Hostname:      id,
		OS:            osName,
		IP:            "10.0.4.20",
		DriverVersion: version,
		Status:        "online",
		LastSeenAt:    time.Now().UTC(),
		CreatedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seeding endpoint %s failed: %v", id, err)
	}
}

func TestAgentConfigReportsUpdateAvailability(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedEndpoint(t, store, "linux-web-01", "Linux 6.8.0-40-generic", "1.0.0")

	// 1. Unknown endpoints are rejected rather than handed a package URL.
	req := httptest.NewRequest("GET", "/api/v1/agent/config?endpoint_id=ghost", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentConfig)(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for unregistered endpoint, got %d", w.Code)
	}

	// 2. A missing endpoint_id is a client error.
	req = httptest.NewRequest("GET", "/api/v1/agent/config", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentConfig)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 without endpoint_id, got %d", w.Code)
	}

	// 3. An endpoint below the bundled version is offered the .deb package.
	req = httptest.NewRequest("GET", "/api/v1/agent/config?endpoint_id=linux-web-01", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentConfig)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 for agent config, got %d (%s)", w.Code, w.Body.String())
	}
	var cfg map[string]interface{}
	json.NewDecoder(w.Body).Decode(&cfg)
	if cfg["update_available"] != true {
		t.Errorf("Expected update_available=true for a 1.0.0 agent, got %v", cfg)
	}
	if cfg["latest_version"] != "1.1.0" {
		t.Errorf("Expected latest_version=1.1.0, got %v", cfg["latest_version"])
	}
	wantURL := "http://10.0.0.57:9999/download/ominull-agent_1.1.0_amd64.deb"
	if cfg["update_url"] != wantURL {
		t.Errorf("Expected update_url %q, got %v", wantURL, cfg["update_url"])
	}

	// 4. An up-to-date endpoint is offered nothing.
	seedEndpoint(t, store, "linux-web-02", "Linux 6.8.0-40-generic", "1.1.0 (eBPF/TC)")
	req = httptest.NewRequest("GET", "/api/v1/agent/config?endpoint_id=linux-web-02", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentConfig)(w, req)
	cfg = map[string]interface{}{}
	json.NewDecoder(w.Body).Decode(&cfg)
	if cfg["update_available"] != false {
		t.Errorf("Expected update_available=false for a current agent, got %v", cfg)
	}
	if _, present := cfg["update_url"]; present {
		t.Errorf("Expected no update_url for a current agent, got %v", cfg["update_url"])
	}
}

func TestAgentsUpdateSchedulingAndStatus(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedEndpoint(t, store, "linux-web-01", "Linux 6.8.0-40-generic", "1.0.0")
	seedEndpoint(t, store, "win-exec-01", "Windows 11 Enterprise (x86_64)", "1.0.0")
	seedEndpoint(t, store, "linux-web-02", "Linux 6.8.0-40-generic", "1.1.0 (eBPF/TC)")

	// 1. Tenant keys must not be able to push fleet-wide agent updates.
	body, _ := json.Marshal(map[string]interface{}{"all": true})
	req := httptest.NewRequest("POST", "/api/v1/agents/update", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "mock_tenant_token")
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentsUpdate)(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for a tenant-scoped update push, got %d", w.Code)
	}

	// 2. Downgrades below the hub's own bundle are refused.
	body, _ = json.Marshal(map[string]interface{}{"all": true, "version": "1.0.0"})
	req = httptest.NewRequest("POST", "/api/v1/agents/update", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentsUpdate)(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for a downgrade request, got %d", w.Code)
	}

	// 3. An admin push schedules Linux endpoints and flags the rest for the push-deployer.
	body, _ = json.Marshal(map[string]interface{}{"all": true})
	req = httptest.NewRequest("POST", "/api/v1/agents/update", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentsUpdate)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 for agent update push, got %d (%s)", w.Code, w.Body.String())
	}
	var push struct {
		DesiredVersion string              `json:"desired_version"`
		Scheduled      []map[string]string `json:"scheduled"`
		Unsupported    []map[string]string `json:"unsupported"`
	}
	json.NewDecoder(w.Body).Decode(&push)
	if push.DesiredVersion != "1.1.0" {
		t.Errorf("Expected desired_version 1.1.0, got %q", push.DesiredVersion)
	}
	if len(push.Scheduled) != 1 || push.Scheduled[0]["endpoint_id"] != "linux-web-01" {
		t.Errorf("Expected only the outdated Linux endpoint scheduled, got %v", push.Scheduled)
	}
	if len(push.Unsupported) != 1 || push.Unsupported[0]["endpoint_id"] != "win-exec-01" {
		t.Errorf("Expected the Windows endpoint reported as unsupported, got %v", push.Unsupported)
	}

	// 4. Status reports both outdated endpoints and the queued job.
	req = httptest.NewRequest("GET", "/api/v1/agents/update-status", nil)
	req.Header.Set("X-API-Key", "mock_admin_token")
	w = httptest.NewRecorder()
	srv.authMiddleware(srv.handleAgentsUpdateStatus)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 for update status, got %d", w.Code)
	}
	var status struct {
		LatestVersion string                   `json:"latest_version"`
		Outdated      []map[string]string      `json:"outdated"`
		Pending       []storage.AgentUpdateJob `json:"pending"`
	}
	json.NewDecoder(w.Body).Decode(&status)
	if status.LatestVersion != "1.1.0" {
		t.Errorf("Expected latest_version 1.1.0, got %q", status.LatestVersion)
	}
	if len(status.Outdated) != 2 {
		t.Errorf("Expected 2 outdated endpoints, got %v", status.Outdated)
	}
	if len(status.Pending) != 1 || status.Pending[0].EndpointID != "linux-web-01" {
		t.Errorf("Expected 1 pending job for linux-web-01, got %v", status.Pending)
	}
}

func TestTelemetryCarriesAndRetiresAgentUpdate(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	seedEndpoint(t, store, "linux-web-01", "Linux 6.8.0-40-generic", "1.0.0")
	if err := store.RequestAgentUpdate("linux-web-01", "1.1.0"); err != nil {
		t.Fatalf("queueing update failed: %v", err)
	}

	postTelemetry := func(version string) map[string]interface{} {
		t.Helper()
		batch, _ := json.Marshal(map[string]interface{}{
			"type":           "telemetry",
			"endpoint_id":    "linux-web-01",
			"hostname":       "linux-web-01",
			"os":             "Linux 6.8.0-40-generic",
			"ip":             "10.0.4.20",
			"driver_version": version,
			"events":         []storage.Event{},
		})
		req := httptest.NewRequest("POST", "/api/v1/events", bytes.NewReader(batch))
		req.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		srv.authMiddleware(srv.handleEvents)(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200 for telemetry post, got %d (%s)", w.Code, w.Body.String())
		}
		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		return resp
	}

	// 1. An outdated agent is handed the package URL on its own telemetry heartbeat.
	resp := postTelemetry("1.0.0")
	update, ok := resp["agent_update"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected agent_update in the telemetry response, got %v", resp)
	}
	if update["version"] != "1.1.0" || update["package"] != "deb" {
		t.Errorf("Unexpected agent_update payload: %v", update)
	}

	// 2. The job stays pending until the agent reports the new version.
	if pending, _ := store.ListPendingAgentUpdates(); len(pending) != 1 {
		t.Errorf("Expected the update job to stay pending, got %v", pending)
	}

	// 3. Reporting the target version closes the job and stops the offer.
	resp = postTelemetry("1.1.0 (eBPF/TC)")
	if _, present := resp["agent_update"]; present {
		t.Errorf("Expected no agent_update once current, got %v", resp["agent_update"])
	}
	pending, _ := store.ListPendingAgentUpdates()
	if len(pending) != 0 {
		t.Errorf("Expected the update job to be retired, got %v", pending)
	}
	job, _ := store.GetAgentUpdateJob("linux-web-01")
	if job == nil || job.CompletedAt == nil {
		t.Errorf("Expected a completed_at timestamp on the retired job, got %v", job)
	}
}

func TestEndpointOrderIsStableAcrossHeartbeats(t *testing.T) {
	srv, store := setupTestServer(t)
	defer store.Close()

	// Enrol out of alphabetical order so a correct sort is observable.
	for _, name := range []string{"zulu-host", "alpha-host", "mike-host"} {
		seedEndpoint(t, store, "ep-"+name, "Linux 6.8.0-40-generic", "1.1.0")
		if err := store.UpsertEndpoint(storage.Endpoint{
			ID: "ep-" + name, TenantID: "default", Hostname: name,
			OS: "Linux 6.8.0-40-generic", IP: "10.0.4.20", DriverVersion: "1.1.0",
			Status: "online", LastSeenAt: time.Now().UTC(), CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("seeding %s failed: %v", name, err)
		}
	}

	order := func() []string {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/endpoints", nil)
		req.Header.Set("X-API-Key", "mock_admin_token")
		w := httptest.NewRecorder()
		srv.authMiddleware(srv.handleEndpoints)(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("Expected 200 listing endpoints, got %d", w.Code)
		}
		var eps []storage.Endpoint
		json.NewDecoder(w.Body).Decode(&eps)
		names := make([]string, 0, len(eps))
		for _, ep := range eps {
			names = append(names, ep.Hostname)
		}
		return names
	}

	want := []string{"alpha-host", "mike-host", "zulu-host"}
	if got := order(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Expected hostname order %v, got %v", want, got)
	}

	// A heartbeat from the alphabetically-first host must not move it to the top or
	// bottom of the list: rows that reshuffle under the operator make an isolate click
	// land on whichever machine slid into that row.
	if err := store.UpsertEndpoint(storage.Endpoint{
		ID: "ep-zulu-host", TenantID: "default", Hostname: "zulu-host",
		OS: "Linux 6.8.0-40-generic", IP: "10.0.4.20", DriverVersion: "1.1.0",
		Status: "online", LastSeenAt: time.Now().UTC().Add(time.Minute), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("heartbeat upsert failed: %v", err)
	}
	if got := order(); !reflect.DeepEqual(got, want) {
		t.Errorf("Order changed after a heartbeat: expected %v, got %v", want, got)
	}
}
