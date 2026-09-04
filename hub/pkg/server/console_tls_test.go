package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/acme"
	"ominull/hub/pkg/configuration"
)

func TestServer_ConsoleTLSListener(t *testing.T) {
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	// 1. Pick free ports for agent TLS and console TLS
	lAgent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind agent listen: %v", err)
	}
	agentAddr := lAgent.Addr().String()
	_ = lAgent.Close()

	lConsole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind console listen: %v", err)
	}
	consoleAddr := lConsole.Addr().String()
	_ = lConsole.Close()

	// 2. Configure agent TLS with ClientCertsRequired
	srv.SetTLS(TLSOptions{
		Listen:      agentAddr,
		ClientCerts: ClientCertsRequired,
	})

	// 3. Configure console TLS with dedicated listener
	srv.SetConsoleTLS(ConsoleTLSOptions{
		Listen:   consoleAddr,
		Hostname: "console.example.invalid",
	})

	// 4. Verify TLS configurations directly
	agentCfg, err := srv.tlsConfig()
	if err != nil {
		t.Fatalf("failed to get agent TLS config: %v", err)
	}
	if agentCfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("expected agent listener ClientAuth to verify client certs, got %v", agentCfg.ClientAuth)
	}
	if agentCfg.ClientCAs == nil {
		t.Fatalf("expected agent listener to have ClientCAs configured")
	}

	consoleCfg, err := srv.consoleTLSConfig()
	if err != nil {
		t.Fatalf("failed to get console TLS config: %v", err)
	}
	// INVARIANT: Console listener MUST NEVER require or challenge for agent client certificates!
	if consoleCfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("INVARIANT VIOLATION: console listener must have ClientAuth=NoClientCert, got %v", consoleCfg.ClientAuth)
	}
	if consoleCfg.ClientCAs != nil {
		t.Fatalf("INVARIANT VIOLATION: console listener must not have ClientCAs pool")
	}

	// 5. Start server in background
	go func() {
		_ = srv.Start("")
	}()
	time.Sleep(100 * time.Millisecond)

	// 6. Connect to console listener with standard browser-like TLS client (no client cert)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // test CA leaf
		},
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	req, err := http.NewRequest(http.MethodGet, "https://"+consoleAddr+"/status", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("X-API-Key", "test-admin-key-12345")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to GET console endpoint over HTTPS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 OK from console listener, got %d: %s", resp.StatusCode, string(body))
	}

	// 7. Verify HSTS header is present on console listener responses
	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		t.Fatalf("expected Strict-Transport-Security header on console response, got empty")
	}

	// 8. Close server and verify clean shutdown
	if err := srv.Close(); err != nil {
		t.Fatalf("srv.Close failed: %v", err)
	}
}

func TestServer_ConsoleTLSSources_OperatorSupplied(t *testing.T) {
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "custom.crt")
	keyFile := filepath.Join(tmpDir, "custom.key")

	// Generate self-signed operator certificate
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(9999),
		Subject:      pkix.Name{CommonName: "custom.example.invalid"},
		DNSNames:     []string{"custom.example.invalid"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	srv.SetConsoleTLS(ConsoleTLSOptions{
		Listen:   ":8443",
		CertFile: certFile,
		KeyFile:  keyFile,
		Hostname: "custom.example.invalid",
	})

	cfg, err := srv.consoleTLSConfig()
	if err != nil {
		t.Fatalf("consoleTLSConfig failed: %v", err)
	}
	if len(cfg.Certificates) == 0 {
		t.Fatalf("expected loaded certificates, got 0")
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("expected ClientAuth=NoClientCert, got %v", cfg.ClientAuth)
	}

	// Verify status endpoint reflects operator-supplied source
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/console/status", nil)
	srv.handleConsoleStatus(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/v1/console/status, got %d", w.Code)
	}
	var res map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if res["source"] != "operator-supplied" {
		t.Fatalf("expected source=operator-supplied, got %v", res["source"])
	}
	if res["hostname"] != "custom.example.invalid" {
		t.Fatalf("expected hostname=custom.example.invalid, got %v", res["hostname"])
	}
}

func TestServer_ConsoleTLSSources_HubCA_GuidedRootTrust(t *testing.T) {
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	srv.SetConsoleTLS(ConsoleTLSOptions{
		Listen:   ":8443",
		Hostname: "hub.example.invalid",
	})

	// 1. Verify console TLS config is issued from hub internal CA
	cfg, err := srv.consoleTLSConfig()
	if err != nil {
		t.Fatalf("consoleTLSConfig failed: %v", err)
	}
	if len(cfg.Certificates) == 0 {
		t.Fatalf("expected certificates from hub CA")
	}

	// 2. Export Hub Root CA PEM
	caPEM := srv.pki.GetCAPEM()
	if len(caPEM) == 0 {
		t.Fatalf("expected non-empty Hub Root CA PEM")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to append Hub Root CA to cert pool")
	}

	// 3. Verify that the issued console leaf verifies cleanly against the exported Root CA
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	opts := x509.VerifyOptions{
		Roots:   roots,
		DNSName: "hub.example.invalid",
	}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("failed to verify console certificate against exported Hub Root CA: %v", err)
	}

	// 4. Test public CA export route /api/v1/pki/ca.crt
	wCA := httptest.NewRecorder()
	rCA := httptest.NewRequest(http.MethodGet, "/api/v1/pki/ca.crt", nil)
	srv.handlePKICACert(wCA, rCA)
	if wCA.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/v1/pki/ca.crt, got %d", wCA.Code)
	}
	if !strings.Contains(wCA.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("expected PEM certificate from /api/v1/pki/ca.crt, got: %s", wCA.Body.String())
	}

	// 5. Test trust instructions route /api/v1/console/trust-instructions
	wTrust := httptest.NewRecorder()
	rTrust := httptest.NewRequest(http.MethodGet, "/api/v1/console/trust-instructions", nil)
	srv.handleConsoleTrustInstructions(wTrust, rTrust)
	if wTrust.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/v1/console/trust-instructions, got %d", wTrust.Code)
	}
	var trustRes map[string]interface{}
	if err := json.Unmarshal(wTrust.Body.Bytes(), &trustRes); err != nil {
		t.Fatalf("unmarshal trust instructions: %v", err)
	}
	instructions, ok := trustRes["instructions"].(map[string]interface{})
	if !ok || instructions["linux_debian"] == "" || instructions["macos"] == "" || instructions["windows"] == "" {
		t.Fatalf("missing per-platform trust instructions in response: %v", trustRes)
	}
}

func TestServer_ConsoleTLSSources_ACMEDNS01(t *testing.T) {
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	tmpDir := t.TempDir()
	certDir := filepath.Join(tmpDir, "certs")
	_ = os.MkdirAll(certDir, 0700)

	// Pre-create cached ACME certificate in certDir
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(7777),
		Subject:      pkix.Name{CommonName: "acme.example.invalid"},
		DNSNames:     []string{"acme.example.invalid"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(filepath.Join(srv.binaryDir, "certs", "console_acme.crt"), certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srv.binaryDir, "certs", "console_acme.key"), keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	mockDNS := acme.NewMockDNSProvider()
	srv.SetConsoleTLS(ConsoleTLSOptions{
		Listen:          ":8443",
		Hostname:        "acme.example.invalid",
		ACMEEnabled:     true,
		ACMEDomain:      "acme.example.invalid",
		ACMEDNSProvider: mockDNS,
	})

	cfg, err := srv.consoleTLSConfig()
	if err != nil {
		t.Fatalf("consoleTLSConfig failed for ACME: %v", err)
	}
	if len(cfg.Certificates) == 0 {
		t.Fatalf("expected loaded ACME certificate")
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("expected ClientAuth=NoClientCert, got %v", cfg.ClientAuth)
	}

	// Verify status endpoint reflects ACME source
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/console/status", nil)
	srv.handleConsoleStatus(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/v1/console/status, got %d", w.Code)
	}
	var res map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if res["source"] != "acme" {
		t.Fatalf("expected source=acme, got %v", res["source"])
	}
}

func TestServer_SetupApply_PersistsConsoleHostname(t *testing.T) {
	srv, _, _, cleanup := setupTestServerWithResponse(t)
	defer cleanup()

	// Authenticate setup session
	reqBody := `{"configuration": {"network_mode": "lan", "console_hostname": "hub.lan", "console_url": "https://hub.lan:8443", "agent_url": "https://hub.lan:9443", "tls_mode": "self-issued", "client_certs": "optional"}, "local_admin_email": "admin@example.invalid"}`
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/setup/apply", strings.NewReader(reqBody))
	r.Header.Set("Content-Type", "application/json")
	srv.handleSetupApply(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("handleSetupApply returned %d: %s", w.Code, w.Body.String())
	}

	// Verify console_hostname was persisted in settings
	val, err := srv.store.GetSetting("setup.console_hostname")
	if err != nil {
		t.Fatalf("GetSetting(setup.console_hostname) failed: %v", err)
	}
	if val != "hub.lan" {
		t.Fatalf("expected setup.console_hostname='hub.lan', got %q", val)
	}

	// Verify setupRuntimeMatches checks console hostname
	cfg := configuration.Config{
		NetworkMode:     "lan",
		ConsoleHostname: "hub.lan",
		ConsoleURL:      "https://hub.lan:8443",
		AgentURL:        "https://hub.lan:9443",
		TLSMode:         "self-issued",
		ClientCerts:     "optional",
	}
	srv.SetTLS(TLSOptions{ClientCerts: ClientCertsOptional})
	srv.consoleTLSOpts.Hostname = "hub.lan"
	srv.hubURL = "https://hub.lan:8443"
	srv.agentHubURL = "https://hub.lan:9443"

	if !srv.setupRuntimeMatches(cfg) {
		t.Fatalf("expected setupRuntimeMatches to return true when runtime matches")
	}

	// Changing hostname without restarting or reconfiguring must return false
	cfgChanged := cfg
	cfgChanged.ConsoleHostname = "different.domain.invalid"
	if srv.setupRuntimeMatches(cfgChanged) {
		t.Fatalf("expected setupRuntimeMatches to return false when ConsoleHostname differs")
	}
}
