package dns

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"ominull/hub/pkg/storage"
)

func TestDNSServerForwardingAndSinkhole(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "dns_test.db")
	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("storage.New() failed: %v", err)
	}
	defer store.Close()

	// Add local block rule and allow rule
	_ = store.SaveDNSRule(&storage.DNSRule{
		Domain: "malicious.sinkhole.test",
		Action: "BLOCK",
		Source: "test",
	})
	_ = store.SaveDNSRule(&storage.DNSRule{
		Domain: "safe.sinkhole.test",
		Action: "ALLOW",
		Source: "test",
	})
	// Block broader domain
	_ = store.SaveDNSRule(&storage.DNSRule{
		Domain: "sinkhole.test",
		Action: "BLOCK",
		Source: "test",
	})

	listenAddr := "127.0.0.1:53554"
	srv := NewServer(listenAddr, []string{"1.1.1.1:53", "8.8.8.8:53"}, store, nil)
	if err := srv.Start(); err != nil {
		t.Fatalf("srv.Start() failed: %v", err)
	}
	defer srv.Stop()

	// Give server a moment to start
	time.Sleep(50 * time.Millisecond)

	c := &dns.Client{Timeout: 2 * time.Second}

	// 1. Test Blocked Subdomain
	mBlock := new(dns.Msg)
	mBlock.SetQuestion("malicious.sinkhole.test.", dns.TypeA)
	rBlock, _, err := c.Exchange(mBlock, listenAddr)
	if err != nil {
		t.Fatalf("query malicious.sinkhole.test failed: %v", err)
	}
	if len(rBlock.Answer) == 0 {
		t.Fatalf("expected sinkhole answer, got none")
	}
	if a, ok := rBlock.Answer[0].(*dns.A); !ok || !a.A.Equal(net.IPv4zero) {
		t.Errorf("expected 0.0.0.0, got: %v", rBlock.Answer[0])
	}

	// 2. Test Inherited Subdomain Block (*.sinkhole.test)
	mSubBlock := new(dns.Msg)
	mSubBlock.SetQuestion("evil.sub.sinkhole.test.", dns.TypeA)
	rSubBlock, _, err := c.Exchange(mSubBlock, listenAddr)
	if err != nil {
		t.Fatalf("query evil.sub.sinkhole.test failed: %v", err)
	}
	if len(rSubBlock.Answer) == 0 {
		t.Fatalf("expected inherited subdomain sinkhole answer, got none")
	}
	if a, ok := rSubBlock.Answer[0].(*dns.A); !ok || !a.A.Equal(net.IPv4zero) {
		t.Errorf("expected 0.0.0.0 for subdomain block, got: %v", rSubBlock.Answer[0])
	}

	// 3. Test Allowlist Override (safe.sinkhole.test is under blocked sinkhole.test, but explicitly allowed)
	allowed, blocked, _ := srv.evaluateDomain("safe.sinkhole.test")
	if !allowed || blocked {
		t.Errorf("expected safe.sinkhole.test to be allowed and not blocked (allowed=%v, blocked=%v)", allowed, blocked)
	}

	// 4. Test Policy Evaluation API
	testRes := srv.TestPolicy("evil.sub.sinkhole.test")
	if testRes["verdict"] != "BLOCK" {
		t.Errorf("TestPolicy expected BLOCK, got %v", testRes["verdict"])
	}

	// 5. Test Status
	status := srv.Status()
	if status["state"] != string(StateProtecting) {
		t.Errorf("expected state protecting, got %v", status["state"])
	}

	// 6. Test Shadow Validator
	shadowAddr := "127.0.0.1:53555"
	if err := ValidateShadowListener(shadowAddr, []string{"1.1.1.1:53"}, "google.com"); err != nil {
		t.Errorf("ValidateShadowListener failed: %v", err)
	}
}
