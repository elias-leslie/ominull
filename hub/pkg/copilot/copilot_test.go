package copilot

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ominull/hub/pkg/storage"
)

func TestCopilotLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_copilot.db")

	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	engine := New(store, Config{
		Provider: ProviderRuleBased,
	})

	ctx := context.Background()

	// 1. Test Chat
	chatResp, err := engine.HandleChat(ctx, "How do I quarantine a rogue node?")
	if err != nil {
		t.Fatalf("HandleChat failed: %v", err)
	}
	if !strings.Contains(chatResp.Reply, "MESH_ISOLATE_PEER") && !strings.Contains(chatResp.Reply, "quarantine") {
		t.Errorf("unexpected chat response: %s", chatResp.Reply)
	}

	// 2. Test Investigate Alert
	alert := storage.AnomalyAlert{
		ID:          "alert-123",
		Title:       "High-Entropy DGA Beaconing Detected",
		AnomalyType: "SUSPICIOUS_DGA_DOMAIN",
		Severity:    "CRITICAL",
		Hostname:    "victim-ws-01",
		EndpointID:  "ep-victim",
		DstIP:       "198.51.100.44",
		DstPort:     443,
		ProcessPath: "/usr/bin/curl",
		Details:     "Entropy: 4.2",
		Timestamp:   time.Now().UTC(),
	}

	report, err := engine.Investigate(ctx, alert)
	if err != nil {
		t.Fatalf("Investigate failed: %v", err)
	}
	if report.AlertID != "alert-123" || report.Severity != "CRITICAL" {
		t.Errorf("unexpected report output: %+v", report)
	}
	if len(report.MitreTechniques) == 0 {
		t.Errorf("expected MITRE techniques to be populated")
	}

	// 3. Test Config Update
	engine.UpdateConfig(Config{
		Provider:    ProviderLocalOllama,
		OllamaURL:   "http://10.0.0.39:11434",
		OllamaModel: "llama3.2",
	})
	cfg := engine.GetConfig()
	if cfg.Provider != ProviderLocalOllama || cfg.OllamaModel != "llama3.2" {
		t.Errorf("config update failed: %+v", cfg)
	}
}
