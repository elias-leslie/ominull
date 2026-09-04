package configuration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurationRejectsPaidOrUnsafeShapes(t *testing.T) {
	bad := Config{NetworkMode: "cloudflare", Cloudflare: true, ConsoleURL: "http://console.invalid", AgentURL: "https://agent.invalid", TLSMode: "self-issued"}
	if err := bad.Validate(); err == nil {
		t.Fatal("cloudflare configuration accepted an HTTP console URL")
	}
	if err := (Config{NetworkMode: "direct", ConsoleURL: "https://u:p@hub.invalid", AgentURL: "https://hub.invalid", TLSMode: "custom"}).Validate(); err == nil {
		t.Fatal("configuration accepted URL userinfo")
	}
	if err := (Config{NetworkMode: "lan", ConsoleURL: "http://hub.local", AgentURL: "http://hub.local", TLSMode: "self-issued"}).Validate(); err == nil {
		t.Fatal("configuration accepted an HTTP agent URL")
	}
	if err := (Config{NetworkMode: "direct", ConsoleURL: "https://console.invalid", AgentURL: "https://agent.invalid", TLSMode: "acme"}).Validate(); err == nil {
		t.Fatal("ACME mode accepted no certificate and key paths even though the hub does not obtain them")
	}
}

func TestEnvironmentAndAtomicWriteNeverContainSecretFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hub.env")
	contents := (Config{NetworkMode: "lan", TLSMode: "self-issued", ConsoleURL: "https://hub.invalid"}).Environment("/var/lib/ominull/ominull.db", "/etc/ominull/admin.key", "/opt/ominull/bin", "/var/lib/ominull/setup.token")
	if strings.Contains(contents, "device_credential") || strings.Contains(contents, "client_secret") || strings.Contains(contents, "service-token") {
		t.Fatalf("environment contains secret material: %q", contents)
	}
	if err := WriteEnvironmentAtomic(path, contents); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != contents {
		t.Fatalf("atomic write mismatch: %v %q", err, got)
	}
	if mode := (func() os.FileMode { info, _ := os.Stat(path); return info.Mode().Perm() })(); mode != 0600 {
		t.Fatalf("configuration mode = %04o, want 0600", mode)
	}
}

func TestClientCertificateModeDefaultsAndValidates(t *testing.T) {
	cfg := (Config{NetworkMode: "lan", ConsoleURL: "http://hub.local", AgentURL: "https://hub.local", TLSMode: "self-issued"}).Normalized()
	if cfg.ClientCerts != "optional" {
		t.Fatalf("default client certificate mode = %q, want optional", cfg.ClientCerts)
	}
	if !strings.Contains(cfg.Environment("db", "admin", "bin", "token"), "OMINULL_CLIENT_CERTS=optional\n") {
		t.Fatal("normalized environment did not keep optional client certificate proof")
	}
	env := cfg.Environment("db", "admin", "bin", "token")
	if !strings.Contains(env, "OMINULL_NETWORK_MODE=lan\n") || !strings.Contains(env, "OMINULL_TLS_MODE=self-issued\n") {
		t.Fatal("environment did not persist non-secret network and TLS modes")
	}
	if err := (Config{NetworkMode: "lan", AgentURL: "https://hub.local", ClientCerts: "unsafe"}).Validate(); err == nil {
		t.Fatal("invalid client certificate mode was accepted")
	}
}

func TestConsoleHostnameAndACMEValidation(t *testing.T) {
	// 1. IP address in ConsoleHostname must be strictly rejected
	badIP := Config{
		NetworkMode:     "lan",
		ConsoleURL:      "https://10.0.0.58:8443",
		AgentURL:        "https://10.0.0.58:9443",
		ConsoleHostname: "10.0.0.58",
	}
	if err := badIP.Validate(); err == nil || !strings.Contains(err.Error(), "not an IP address") {
		t.Fatalf("expected error rejecting IP address for ConsoleHostname, got: %v", err)
	}

	// 2. Scheme or port in ConsoleHostname must be rejected
	badScheme := Config{
		NetworkMode:     "lan",
		ConsoleURL:      "https://hub.lan:8443",
		AgentURL:        "https://hub.lan:9443",
		ConsoleHostname: "https://hub.lan:8443",
	}
	if err := badScheme.Validate(); err == nil || !strings.Contains(err.Error(), "without scheme, port, or path") {
		t.Fatalf("expected error rejecting scheme/port in ConsoleHostname, got: %v", err)
	}

	// 3. Valid domain name in ConsoleHostname must be accepted
	validDomain := Config{
		NetworkMode:        "direct",
		ConsoleURL:         "https://omi.example.invalid:8443",
		AgentURL:           "https://agent.example.invalid:9443",
		ConsoleHostname:    "omi.example.invalid",
		ConsoleTLSListen:   ":8443",
		ConsoleTLSCertFile: "/etc/ominull/console.crt",
		ConsoleTLSKeyFile:  "/etc/ominull/console.key",
		TLSMode:            "custom",
	}
	if err := validDomain.Validate(); err != nil {
		t.Fatalf("valid domain config rejected: %v", err)
	}

	// 4. Normalized defaults ConsoleHostname from ConsoleURL when not an IP
	norm := (Config{
		NetworkMode: "lan",
		ConsoleURL:  "https://hub.lan:8443",
		AgentURL:    "https://hub.lan:9443",
	}).Normalized()
	if norm.ConsoleHostname != "hub.lan" {
		t.Fatalf("expected ConsoleHostname normalized to 'hub.lan', got %q", norm.ConsoleHostname)
	}

	// 5. ACME DNS-01 validation
	acmeCfg := Config{
		NetworkMode:     "direct",
		ConsoleURL:      "https://omi.example.invalid:8443",
		AgentURL:        "https://agent.example.invalid:9443",
		ConsoleHostname: "omi.example.invalid",
		TLSMode:         "acme",
		ACMEEnabled:     true,
		ACMEEmail:       "ops@example.invalid",
	}
	if err := acmeCfg.Validate(); err != nil {
		t.Fatalf("valid ACME DNS-01 config rejected: %v", err)
	}

	env := acmeCfg.Environment("/var/lib/ominull/db", "/etc/ominull/admin.key", "/bin", "/token")
	if !strings.Contains(env, "OMINULL_CONSOLE_HOSTNAME=omi.example.invalid\n") {
		t.Fatalf("missing OMINULL_CONSOLE_HOSTNAME in env: %s", env)
	}
	if !strings.Contains(env, "OMINULL_ACME_ENABLED=true\n") {
		t.Fatalf("missing OMINULL_ACME_ENABLED in env: %s", env)
	}
	if !strings.Contains(env, "OMINULL_ACME_DOMAIN=omi.example.invalid\n") {
		t.Fatalf("missing OMINULL_ACME_DOMAIN in env: %s", env)
	}
}
