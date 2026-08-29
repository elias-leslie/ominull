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
	_ = engine.UpdateConfig(Config{
		Provider:    ProviderLocalOllama,
		OllamaURL:   "http://10.0.0.39:11434",
		OllamaModel: "llama3.2",
	})
	cfg := engine.GetConfig()
	if cfg.Provider != ProviderLocalOllama || cfg.OllamaModel != "llama3.2" {
		t.Errorf("config update failed: %+v", cfg)
	}
}

// TestUnreachableProviderIsReportedAsDegraded is the honesty contract. The
// engine answers from a built-in rule set when the configured model cannot be
// reached, and that answer is confident, formatted like the real thing, and
// entirely generic. Reporting it as the model's work - which is what shipped
// through v1.4.4 - tells an operator a model looked at their alert when nothing
// did, so what must never regress is the label, not the fallback.
func TestUnreachableProviderIsReportedAsDegraded(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "copilot_degraded.db"))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer store.Close()

	// Port 1 on the loopback: nothing listens, and it fails immediately rather
	// than making the test wait out a timeout.
	engine := New(store, Config{
		Provider:    ProviderLocalOllama,
		OllamaURL:   "http://127.0.0.1:1",
		OllamaModel: "llama3.2",
	})

	resp, err := engine.HandleChat(context.Background(), "what is happening on the network?")
	if err != nil {
		t.Fatalf("HandleChat failed: %v", err)
	}
	if resp.Reply == "" {
		t.Fatal("expected a rule-set answer rather than nothing")
	}
	if !resp.Degraded {
		t.Error("an unreachable provider was not reported as degraded")
	}
	if resp.Provider != string(ProviderRuleBased) {
		t.Errorf("a rule-set answer was attributed to %q", resp.Provider)
	}
	if resp.Notice == "" {
		t.Error("degraded answer carries no explanation of why")
	}

	// The same has to hold for an investigation, which reads even more like
	// analysis than a chat reply does.
	report, err := engine.Investigate(context.Background(), storage.AnomalyAlert{
		ID: "alert-degraded", Title: "beaconing", Severity: "HIGH",
	})
	if err != nil {
		t.Fatalf("Investigate failed: %v", err)
	}
	if !report.Degraded || report.Provider != string(ProviderRuleBased) {
		t.Errorf("investigation attributed to %q, degraded=%v", report.Provider, report.Degraded)
	}

	// A provider that answers must be reported as itself, or the flag is
	// useless noise.
	_ = engine.UpdateConfig(Config{Provider: ProviderRuleBased})
	plain, err := engine.HandleChat(context.Background(), "status")
	if err != nil {
		t.Fatalf("HandleChat failed: %v", err)
	}
	if plain.Degraded {
		t.Error("the rule set answering as the configured provider is not a degradation")
	}
}

// TestUnreachableProviderDegradesBeforeTheHubGivesUp pins the other half of the
// live failure. The hub's WriteTimeout is 30s; the copilot's HTTP client used
// to allow 45s, so a provider that never answered outlived the response and the
// console got an empty body after exactly thirty seconds instead of the
// fallback. What matters is not the exact numbers but that a dead provider
// resolves well inside the window the hub will hold a response open for.
func TestUnreachableProviderDegradesBeforeTheHubGivesUp(t *testing.T) {
	store, err := storage.New(filepath.Join(t.TempDir(), "copilot_timeout.db"))
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}
	defer store.Close()

	// TEST-NET-1: routable nowhere, so this blackholes in connect rather than
	// being refused - the shape of the real failure, where the configured
	// address simply did not exist on the network.
	engine := New(store, Config{
		Provider:    ProviderLocalOllama,
		OllamaURL:   "http://192.0.2.1:11434",
		OllamaModel: "llama3.2",
	})

	start := time.Now()
	answer := engine.Ask(context.Background(), "system", "status")
	elapsed := time.Since(start)

	if elapsed > 15*time.Second {
		t.Errorf("a blackholed provider took %s to degrade; the hub closes the response at 30s", elapsed)
	}
	if !answer.Degraded || answer.Provider != ProviderRuleBased {
		t.Errorf("expected a labelled rule-set answer, got provider=%q degraded=%v", answer.Provider, answer.Degraded)
	}
}

// A copilot configuration used to live only in the running process, so an
// operator who selected a provider through the API had it silently replaced by
// the compiled-in default at the next hub restart. This deployment went back to
// pointing at an unroutable placeholder that way, twice, with nothing in the
// logs to say a setting had been discarded.
func TestConfigurationSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.New(filepath.Join(dir, "copilot.db"))
	if err != nil {
		t.Fatalf("storage init failed: %v", err)
	}
	defer store.Close()

	engine := New(store, Config{Provider: ProviderLocalOllama, OllamaURL: "http://192.0.2.1:11434"})
	if err := engine.UpdateConfig(Config{Provider: ProviderRuleBased}); err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	// A second engine over the same store is what a restart looks like. The
	// compiled-in argument is deliberately the old placeholder: a stored
	// setting has to outrank it, or configuring the copilot means nothing.
	restarted := New(store, Config{Provider: ProviderLocalOllama, OllamaURL: "http://192.0.2.1:11434"})
	if got := restarted.GetConfig().Provider; got != ProviderRuleBased {
		t.Errorf("after a restart the copilot reports provider %q; the operator selected %q", got, ProviderRuleBased)
	}
}
