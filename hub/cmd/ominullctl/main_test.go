package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ominull/hub/pkg/setup"
)

func TestOminullctl_SetupToken(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ominullctl-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tokenPath := filepath.Join(tempDir, "setup.token")

	// Ensure token
	if err := setup.Ensure(tokenPath); err != nil {
		t.Fatalf("setup.Ensure failed: %v", err)
	}

	tok1, err := currentToken(tokenPath)
	if err != nil {
		t.Fatalf("currentToken failed: %v", err)
	}
	if !strings.HasPrefix(tok1, "oms_") || len(tok1) < 64 {
		t.Fatalf("expected valid oms_ token, got %q", tok1)
	}

	// Rotate token
	tok2, err := setup.Rotate(tokenPath)
	if err != nil {
		t.Fatalf("setup.Rotate failed: %v", err)
	}
	if tok1 == tok2 {
		t.Fatalf("expected rotated token to differ")
	}

	tokRead, err := currentToken(tokenPath)
	if err != nil {
		t.Fatalf("currentToken after rotate failed: %v", err)
	}
	if tokRead != tok2 {
		t.Fatalf("token mismatch: %s vs %s", tokRead, tok2)
	}
}

func TestOminullctl_ParseFlags(t *testing.T) {
	args := []string{"--url", "http://10.0.0.1:9999", "--json", "--tenant", "tenant-xyz", "--limit", "25", "endpoints", "list"}
	cfg, rest := parseGlobalFlags(args)

	if cfg.HubURL != "http://10.0.0.1:9999" {
		t.Fatalf("unexpected HubURL: %s", cfg.HubURL)
	}
	if !cfg.JSONOutput {
		t.Fatalf("expected JSONOutput to be true")
	}
	if cfg.TenantID != "tenant-xyz" {
		t.Fatalf("unexpected TenantID: %s", cfg.TenantID)
	}
	if cfg.Limit != 25 {
		t.Fatalf("unexpected Limit: %d", cfg.Limit)
	}
	if len(rest) != 2 || rest[0] != "endpoints" || rest[1] != "list" {
		t.Fatalf("unexpected rest args: %v", rest)
	}
}

func TestOminullctl_NoPlaintextEnvAPIKey(t *testing.T) {
	t.Setenv("OMINULL_API_KEY", "should-not-be-used")
	t.Setenv("OMINULL_API_KEY_FILE", "/nonexistent/test/admin.key")

	cfg, _ := parseGlobalFlags([]string{"endpoints", "list"})
	if cfg.APIKey != "" {
		t.Fatalf("OMINULL_API_KEY environment variable was read; expected empty APIKey, got %q", cfg.APIKey)
	}
}

func TestOminullctl_ConsoleOnlyMutationsForbidden(t *testing.T) {
	client := newAPIClient(CLIConfig{})

	// 1. Shell open, exec, attach forbidden
	for _, subcmd := range []string{"open", "exec", "attach"} {
		err := client.cmdShell([]string{subcmd, "ep-1"})
		if err == nil {
			t.Fatalf("cmdShell with %q expected error, got nil", subcmd)
		}
		if !strings.Contains(err.Error(), "console-only and requires dual-operator authorization") {
			t.Fatalf("cmdShell with %q expected console-only authorization error, got: %v", subcmd, err)
		}
	}

	// 2. Scripts run, schedule forbidden
	for _, subcmd := range []string{"run", "schedule"} {
		err := client.cmdScripts([]string{subcmd, "scr-1"})
		if err == nil {
			t.Fatalf("cmdScripts with %q expected error, got nil", subcmd)
		}
		if !strings.Contains(err.Error(), "console-only and require dual-operator authorization") {
			t.Fatalf("cmdScripts with %q expected console-only authorization error, got: %v", subcmd, err)
		}
	}

	// 3. Forensics launch, collect forbidden
	for _, subcmd := range []string{"launch", "collect"} {
		err := client.cmdForensics([]string{subcmd, "ep-1"})
		if err == nil {
			t.Fatalf("cmdForensics with %q expected error, got nil", subcmd)
		}
		if !strings.Contains(err.Error(), "console-only and requires dual-operator authorization") {
			t.Fatalf("cmdForensics with %q expected console-only authorization error, got: %v", subcmd, err)
		}
	}
}

func TestOminullctl_CommandParity(t *testing.T) {
	// Mock hub server providing endpoints matching scripts/ominull-cli
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/hierarchy", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-key-123" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"online","tenants":["default"]}`))
	})

	mux.HandleFunc("/api/v1/endpoints", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"ep-test-1","hostname":"host-test","ip":"10.0.0.100","status":"online"}]`))
	})

	mux.HandleFunc("/api/v1/scanner/scan", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"scan_id":"scan-12345","status":"initiated"}`))
	})

	mux.HandleFunc("/api/v1/scanner/results", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"ip":"10.0.0.100","name":"Workstation","vendor":"Dell","category":"workstation"}]`))
	})

	mux.HandleFunc("/api/v1/scanner/feedback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"recorded"}`))
	})

	mux.HandleFunc("/api/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"alert_id":"alt-1","severity":"high","title":"Beaconing detected"}]`))
	})

	mux.HandleFunc("/api/v1/mesh/quarantine", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"quarantined","target_ip":"10.0.0.250"}`))
	})

	mux.HandleFunc("/api/v1/mesh/unquarantine", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"released","target_ip":"10.0.0.250"}`))
	})

	mux.HandleFunc("/api/v1/agents/update-status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"current_version":"1.8.3","fleet_total":1,"up_to_date":1}`))
	})

	mux.HandleFunc("/api/v1/agents/update", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"published"}`))
	})

	mux.HandleFunc("/api/v1/enrolment/install-errors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"err-1","message":"curl failed"}]`))
	})

	mux.HandleFunc("/api/v1/response/jobs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"job_id":"job-1","state":"succeeded"}]`))
	})

	mux.HandleFunc("/api/v1/response/jobs/cancel", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"cancelled","job_id":"job-1"}`))
	})

	mux.HandleFunc("/api/v1/response/auth/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"online","signers_count":2}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newAPIClient(CLIConfig{
		HubURL:     server.URL,
		APIKey:     "test-key-123",
		TenantID:   "default",
		JSONOutput: true,
	})

	// Test 1: status command
	if err := client.cmdStatus(nil); err != nil {
		t.Fatalf("cmdStatus failed: %v", err)
	}

	// Test 2: endpoints list & show
	if err := client.cmdEndpoints([]string{"list"}); err != nil {
		t.Fatalf("cmdEndpoints list failed: %v", err)
	}
	if err := client.cmdEndpoints([]string{"show", "ep-test-1"}); err != nil {
		t.Fatalf("cmdEndpoints show failed: %v", err)
	}

	// Test 3: scanner subcommands
	if err := client.cmdScanner([]string{"assets"}); err != nil {
		t.Fatalf("cmdScanner assets failed: %v", err)
	}
	if err := client.cmdScanner([]string{"scan", "10.0.0.0/24", "standard"}); err != nil {
		t.Fatalf("cmdScanner scan failed: %v", err)
	}
	if err := client.cmdScanner([]string{"train", "10.0.0.100", "Workstation", "Dell", "desktop"}); err != nil {
		t.Fatalf("cmdScanner train failed: %v", err)
	}

	// Test 4: alerts list
	if err := client.cmdAlerts(nil); err != nil {
		t.Fatalf("cmdAlerts failed: %v", err)
	}

	// Test 5: mesh quarantine & release
	if err := client.cmdMesh([]string{"quarantine", "10.0.0.250", "00:11:22:33:44:55", "test"}); err != nil {
		t.Fatalf("cmdMesh quarantine failed: %v", err)
	}
	if err := client.cmdMesh([]string{"release", "10.0.0.250"}); err != nil {
		t.Fatalf("cmdMesh release failed: %v", err)
	}

	// Test 6: agents versions & update
	if err := client.cmdAgents([]string{"versions"}); err != nil {
		t.Fatalf("cmdAgents versions failed: %v", err)
	}
	if err := client.cmdAgents([]string{"update", "all", "1.8.3"}); err != nil {
		t.Fatalf("cmdAgents update all failed: %v", err)
	}

	// Test 7: install reports
	if err := client.cmdInstall([]string{"reports"}); err != nil {
		t.Fatalf("cmdInstall reports failed: %v", err)
	}

	// Test 8: response jobs list & cancel
	if err := client.cmdResponse([]string{"jobs", "list"}); err != nil {
		t.Fatalf("cmdResponse jobs list failed: %v", err)
	}
	if err := client.cmdResponse([]string{"jobs", "cancel", "job-1"}); err != nil {
		t.Fatalf("cmdResponse jobs cancel failed: %v", err)
	}

	// Test 9: response-auth status
	if err := client.cmdResponseAuth([]string{"status"}); err != nil {
		t.Fatalf("cmdResponseAuth status failed: %v", err)
	}
}

func TestOminullctl_DirectAliasesDispatch(t *testing.T) {
	// Verifies that legacy commands map cleanly to their corresponding API client actions
	mux := http.NewServeMux()
	called := make(map[string]bool)

	mux.HandleFunc("/api/v1/scanner/results", func(w http.ResponseWriter, r *http.Request) {
		called["assets"] = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/api/v1/mesh/quarantine", func(w http.ResponseWriter, r *http.Request) {
		called["quarantine"] = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/api/v1/mesh/unquarantine", func(w http.ResponseWriter, r *http.Request) {
		called["unquarantine"] = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/api/v1/agents/update-status", func(w http.ResponseWriter, r *http.Request) {
		called["agent-versions"] = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newAPIClient(CLIConfig{HubURL: server.URL, APIKey: "test"})

	_ = client.cmdScanner([]string{"assets"})
	_ = client.cmdMesh([]string{"quarantine", "10.0.0.1"})
	_ = client.cmdMesh([]string{"release", "10.0.0.1"})
	_ = client.cmdAgents([]string{"versions"})

	for _, k := range []string{"assets", "quarantine", "unquarantine", "agent-versions"} {
		if !called[k] {
			t.Fatalf("expected handler for %s to have been called", k)
		}
	}
}
