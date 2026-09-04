package server

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
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
