package main

import (
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

func TestOminullctl_ShellForbiddenSubcommands(t *testing.T) {
	client := newAPIClient(CLIConfig{})

	for _, subcmd := range []string{"open", "exec", "unknown"} {
		err := client.cmdShell([]string{subcmd, "ep-1"})
		if err == nil {
			t.Fatalf("cmdShell with %q expected error, got nil", subcmd)
		}
		if !strings.Contains(err.Error(), "usage: ominullctl shell sessions|show|close") {
			t.Fatalf("cmdShell with %q expected usage error, got: %v", subcmd, err)
		}
	}
}
