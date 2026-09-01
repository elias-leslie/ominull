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
