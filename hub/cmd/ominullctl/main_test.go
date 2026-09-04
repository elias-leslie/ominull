package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/evidence"
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

func TestOminullctl_ForensicsVerify(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ctl-forensics-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate endpoint keypair
	epPub, epPriv, _ := ed25519.GenerateKey(rand.Reader)
	epPubHex := hex.EncodeToString(epPub)

	// Create local artifact file
	artContent := []byte("process table data: pid 1 init\n")
	artPath := filepath.Join(tempDir, "proc.txt")
	_ = os.WriteFile(artPath, artContent, 0600)

	// Create signed manifest
	manifest := evidence.Manifest{
		BundleID:    "bundle-verify-1",
		EndpointID:  "ep-test-1",
		TenantID:    "default",
		JobID:       "job-1",
		Profile:     "diagnostic",
		CollectedAt: time.Now().UTC(),
		Items: []evidence.ManifestItem{
			{Name: "proc.txt", SizeBytes: int64(len(artContent)), SHA256: evidence.ComputeDigest(artContent), CollectorStatus: "collected"},
		},
	}
	manifestSig := ed25519.Sign(epPriv, manifest.CanonicalBytes())
	manifest.Signature = hex.EncodeToString(manifestSig)

	manifestBytes, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tempDir, "manifest.json")
	_ = os.WriteFile(manifestPath, manifestBytes, 0600)

	// Generate hub receipt keypair
	hubPub, hubPriv, _ := ed25519.GenerateKey(rand.Reader)
	hubPubHex := hex.EncodeToString(hubPub)

	// Create signed receipt
	receipt := evidence.EvidenceReceipt{
		ReceiptID:             "rec-1",
		BundleID:              manifest.BundleID,
		TenantID:              manifest.TenantID,
		EndpointID:            manifest.EndpointID,
		ManifestSHA256:        evidence.ComputeDigest(manifest.CanonicalBytes()),
		StorageObjectsSHA256:  "sha-storage-123",
		PreviousReceiptSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		IngestedAt:            time.Now().UTC(),
	}
	receipt.ReceiptHash = receipt.ComputeReceiptHash()
	receiptSig := ed25519.Sign(hubPriv, receipt.CanonicalBytes())
	receipt.ReceiptSignature = hex.EncodeToString(receiptSig)

	receiptBytes, _ := json.Marshal(receipt)
	receiptPath := filepath.Join(tempDir, "receipt.json")
	_ = os.WriteFile(receiptPath, receiptBytes, 0600)

	client := newAPIClient(CLIConfig{JSONOutput: true})

	// 1. Full verification with key, receipt, and hub-key
	verifyArgs := []string{"verify", manifestPath, "--key", epPubHex, "--receipt", receiptPath, "--hub-key", hubPubHex}
	if err := client.cmdForensics(verifyArgs); err != nil {
		t.Fatalf("full forensics verify failed: %v", err)
	}

	// 2. Corrupt key fails
	badKeyArgs := []string{"verify", manifestPath, "--key", "deadbeef12345678"}
	if err := client.cmdForensics(badKeyArgs); err == nil {
		t.Fatal("expected invalid key format to fail verification")
	}

	// 3. Tampered local file fails
	_ = os.WriteFile(artPath, []byte("tampered data"), 0600)
	if err := client.cmdForensics(verifyArgs); err == nil {
		t.Fatal("expected tampered local artifact to fail verification")
	}
}

func TestOminullctl_ConsoleCommands(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Setup mock hub server responding to CA download and console status
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIB...test...CA\n-----END CERTIFICATE-----\n")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/pki/ca.crt":
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.Write(caPEM)
		case "/api/v1/console/status":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"listen":":8443","hostname":"omi.example.invalid","webauthn_rp_id":"omi.example.invalid","source":"hub-ca","hsts":true,"client_auth":"NoClientCert"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client := newAPIClient(CLIConfig{HubURL: ts.URL, JSONOutput: true})

	// 2. Test export-ca with API fallback and --out file
	outFile := filepath.Join(tempDir, "exported-ca.crt")
	if err := client.cmdConsole([]string{"export-ca", "--out", outFile, "--path", "/nonexistent/ca.crt"}); err != nil {
		t.Fatalf("cmdConsole export-ca failed: %v", err)
	}
	content, err := os.ReadFile(outFile)
	if err != nil || !strings.Contains(string(content), "BEGIN CERTIFICATE") {
		t.Fatalf("failed to read exported CA from %s: %v", outFile, err)
	}

	// 3. Test export-ca reading directly from disk
	localCA := filepath.Join(tempDir, "local-ca.crt")
	_ = os.WriteFile(localCA, []byte("-----BEGIN CERTIFICATE-----\nlocal...CA\n-----END CERTIFICATE-----\n"), 0644)
	outLocal := filepath.Join(tempDir, "out-local.crt")
	if err := client.cmdConsole([]string{"export-ca", "--out", outLocal, "--path", localCA}); err != nil {
		t.Fatalf("cmdConsole export-ca with local path failed: %v", err)
	}
	readLocal, _ := os.ReadFile(outLocal)
	if !strings.Contains(string(readLocal), "local...CA") {
		t.Fatalf("expected local CA content, got: %s", string(readLocal))
	}

	// 4. Test trust-instructions
	if err := client.cmdConsole([]string{"trust-instructions"}); err != nil {
		t.Fatalf("cmdConsole trust-instructions failed: %v", err)
	}

	// 5. Test status
	if err := client.cmdConsole([]string{"status"}); err != nil {
		t.Fatalf("cmdConsole status failed: %v", err)
	}

	// 6. Unknown subcommand fails
	if err := client.cmdConsole([]string{"unknown-subcommand"}); err == nil {
		t.Fatalf("expected unknown console subcommand to fail")
	}
}

func TestOminullctl_ScriptsCommands(t *testing.T) {
	tempDir := t.TempDir()

	// Mock hub server for scripts API
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/scripts", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			id := r.URL.Query().Get("id")
			ver := r.URL.Query().Get("version")
			if id == "scr-1" && ver == "1" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"script_id":             "scr-1",
					"version":               1,
					"digest_sha256":         "abc123digest",
					"source":                "echo hello",
					"parameter_schema_json": `{"parameters":[]}`,
					"created_at":            "2026-09-04T12:00:00Z",
					"created_by":            "operator",
				})
				return
			}
			if id == "scr-1" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"id":             "scr-1",
					"name":           "Test Script",
					"description":    "A test script",
					"interpreter":    "/bin/sh",
					"latest_version": 1,
					"retired":        false,
					"created_at":     "2026-09-04T12:00:00Z",
					"updated_at":     "2026-09-04T12:00:00Z",
					"versions": []map[string]interface{}{
						{
							"version":       1,
							"digest_sha256": "abc123digest",
							"created_at":    "2026-09-04T12:00:00Z",
							"created_by":    "operator",
						},
					},
				})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"scripts": []map[string]interface{}{
					{
						"id":             "scr-1",
						"name":           "Test Script",
						"description":    "A test script",
						"interpreter":    "/bin/sh",
						"latest_version": 1,
						"retired":        false,
					},
				},
			})
		case http.MethodPost:
			var req map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			if id, ok := req["id"].(string); ok && id != "" {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"script_id":     id,
					"version":       2,
					"digest_sha256": "updated123digest",
					"created_by":    "operator",
				})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"script": map[string]interface{}{
					"id":          "scr-created-1",
					"name":        req["name"],
					"interpreter": req["interpreter"],
				},
				"version": map[string]interface{}{
					"version":       1,
					"digest_sha256": "new123digest",
				},
			})
		case http.MethodDelete:
			id := r.URL.Query().Get("id")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"retired": true,
				"id":      id,
			})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newAPIClient(CLIConfig{
		HubURL:     server.URL,
		APIKey:     "test-key",
		TenantID:   "default",
		JSONOutput: true,
	})

	// 1. List
	if err := client.cmdScripts([]string{"list"}); err != nil {
		t.Fatalf("cmdScripts list failed: %v", err)
	}

	// 2. Show script
	if err := client.cmdScripts([]string{"show", "scr-1"}); err != nil {
		t.Fatalf("cmdScripts show failed: %v", err)
	}

	// 3. Show version
	if err := client.cmdScripts([]string{"show", "scr-1", "--version", "1"}); err != nil {
		t.Fatalf("cmdScripts show with version failed: %v", err)
	}

	// 4. Create
	srcFile := filepath.Join(tempDir, "script.sh")
	if err := os.WriteFile(srcFile, []byte("echo 42"), 0644); err != nil {
		t.Fatalf("write srcFile failed: %v", err)
	}
	schemaFile := filepath.Join(tempDir, "schema.json")
	if err := os.WriteFile(schemaFile, []byte(`{"parameters":[]}`), 0644); err != nil {
		t.Fatalf("write schemaFile failed: %v", err)
	}

	if err := client.cmdScripts([]string{"create", "--name", "Echo 42", "--interpreter", "/bin/sh", "--source-file", srcFile, "--schema-file", schemaFile}); err != nil {
		t.Fatalf("cmdScripts create failed: %v", err)
	}

	// 5. Update
	if err := client.cmdScripts([]string{"update", "scr-1", "--source-file", srcFile}); err != nil {
		t.Fatalf("cmdScripts update failed: %v", err)
	}

	// 6. Retire
	if err := client.cmdScripts([]string{"retire", "scr-1"}); err != nil {
		t.Fatalf("cmdScripts retire failed: %v", err)
	}

	// 7. Run and schedule are forbidden
	if err := client.cmdScripts([]string{"run", "scr-1"}); err == nil {
		t.Fatalf("cmdScripts run expected error")
	}
	if err := client.cmdScripts([]string{"schedule", "scr-1"}); err == nil {
		t.Fatalf("cmdScripts schedule expected error")
	}

	// 8. Missing arguments validation
	if err := client.cmdScripts([]string{"show"}); err == nil {
		t.Fatalf("cmdScripts show without id expected error")
	}
	if err := client.cmdScripts([]string{"create"}); err == nil {
		t.Fatalf("cmdScripts create without flags expected error")
	}
	if err := client.cmdScripts([]string{"update", "scr-1"}); err == nil {
		t.Fatalf("cmdScripts update without source file expected error")
	}
	if err := client.cmdScripts([]string{"retire"}); err == nil {
		t.Fatalf("cmdScripts retire without id expected error")
	}
}

