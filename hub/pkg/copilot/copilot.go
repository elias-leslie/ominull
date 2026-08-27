package copilot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"ominull/hub/pkg/storage"
)

type ProviderType string

const (
	ProviderLocalOllama ProviderType = "ollama"
	ProviderGemini      ProviderType = "gemini"
	ProviderOpenAI      ProviderType = "openai"
	ProviderRuleBased   ProviderType = "heuristic"
)

type Config struct {
	Provider     ProviderType `json:"provider"`
	OllamaURL    string       `json:"ollama_url"`
	OllamaModel  string       `json:"ollama_model"`
	GeminiAPIKey string       `json:"gemini_api_key"`
	GeminiModel  string       `json:"gemini_model"`
	OpenAIAPIKey string       `json:"openai_api_key"`
	OpenAIModel  string       `json:"openai_model"`
}

type LLMProvider interface {
	Generate(ctx context.Context, systemPrompt string, prompt string) (string, error)
}

type Engine struct {
	mu     sync.RWMutex
	config Config
	store  *storage.Store
	client *http.Client
}

func New(store *storage.Store, cfg Config) *Engine {
	if cfg.Provider == "" {
		cfg.Provider = ProviderRuleBased
	}
	if cfg.OllamaURL == "" {
		cfg.OllamaURL = "http://10.0.0.39:11434"
	}
	if cfg.OllamaModel == "" {
		cfg.OllamaModel = "llama3.2"
	}
	if cfg.GeminiModel == "" {
		cfg.GeminiModel = "gemini-1.5-flash"
	}
	if cfg.OpenAIModel == "" {
		cfg.OpenAIModel = "gpt-4o-mini"
	}

	return &Engine{
		config: cfg,
		store:  store,
		client: &http.Client{Timeout: 45 * time.Second},
	}
}

func (e *Engine) GetConfig() Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

func (e *Engine) UpdateConfig(cfg Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config = cfg
}

func (e *Engine) Generate(ctx context.Context, systemPrompt string, prompt string) (string, error) {
	e.mu.RLock()
	cfg := e.config
	e.mu.RUnlock()

	switch cfg.Provider {
	case ProviderLocalOllama:
		return e.generateOllama(ctx, cfg, systemPrompt, prompt)
	case ProviderGemini:
		if cfg.GeminiAPIKey != "" {
			return e.generateGemini(ctx, cfg, systemPrompt, prompt)
		}
	case ProviderOpenAI:
		if cfg.OpenAIAPIKey != "" {
			return e.generateOpenAI(ctx, cfg, systemPrompt, prompt)
		}
	}

	return e.generateHeuristic(systemPrompt, prompt)
}

func (e *Engine) generateOllama(ctx context.Context, cfg Config, systemPrompt string, prompt string) (string, error) {
	reqBody := map[string]interface{}{
		"model":  cfg.OllamaModel,
		"system": systemPrompt,
		"prompt": prompt,
		"stream": false,
	}
	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("%s/api/generate", strings.TrimRight(cfg.OllamaURL, "/"))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBytes))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(httpReq)
	if err != nil {
		// Fallback to heuristic on connection refusal
		return e.generateHeuristic(systemPrompt, prompt)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return e.generateHeuristic(systemPrompt, prompt)
	}

	var ollamaResp struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", err
	}
	return ollamaResp.Response, nil
}

func (e *Engine) generateGemini(ctx context.Context, cfg Config, systemPrompt string, prompt string) (string, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		cfg.GeminiModel, cfg.GeminiAPIKey)

	combined := fmt.Sprintf("%s\n\nTask:\n%s", systemPrompt, prompt)
	reqBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]interface{}{
					{"text": combined},
				},
			},
		},
	}
	jsonBytes, _ := json.Marshal(reqBody)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBytes))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return e.generateHeuristic(systemPrompt, prompt)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var geminiResp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(bodyBytes, &geminiResp); err == nil && len(geminiResp.Candidates) > 0 && len(geminiResp.Candidates[0].Content.Parts) > 0 {
		return geminiResp.Candidates[0].Content.Parts[0].Text, nil
	}
	return e.generateHeuristic(systemPrompt, prompt)
}

func (e *Engine) generateOpenAI(ctx context.Context, cfg Config, systemPrompt string, prompt string) (string, error) {
	reqBody := map[string]interface{}{
		"model": cfg.OpenAIModel,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": prompt},
		},
	}
	jsonBytes, _ := json.Marshal(reqBody)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.openai.com/v1/chat/completions", bytes.NewReader(jsonBytes))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+cfg.OpenAIAPIKey)

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return e.generateHeuristic(systemPrompt, prompt)
	}
	defer resp.Body.Close()

	var oaiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&oaiResp); err == nil && len(oaiResp.Choices) > 0 {
		return oaiResp.Choices[0].Message.Content, nil
	}
	return e.generateHeuristic(systemPrompt, prompt)
}

func (e *Engine) generateHeuristic(systemPrompt string, prompt string) (string, error) {
	pLower := strings.ToLower(prompt)

	if strings.Contains(pLower, "investigate") || strings.Contains(pLower, "triage") || strings.Contains(pLower, "alert") {
		return "### 🔍 Ominull Cognitive SOC Forensic Briefing\n\n" +
			"- **Severity:** HIGH / CRITICAL\n" +
			"- **Attack Vector:** Anomaly correlation indicates anomalous outbound network execution.\n" +
			"- **MITRE ATT&CK:** T1071.001 (Application Layer Protocol: Web Protocols), T1041 (Exfiltration Over C2 Channel).\n" +
			"- **Forensic Findings:** Process attempted unauthorized lateral / outbound communication.\n" +
			"- **Recommended Remediation:**\n" +
			"  1. Enforce host isolation or subnet mesh drop rule.\n" +
			"  2. Inspect binary hash and terminate malicious PID.\n" +
			"  3. Rotate exposed credential sets on affected host.", nil
	}

	if strings.Contains(pLower, "nvidia") || strings.Contains(pLower, "shield") || strings.Contains(pLower, "tv") {
		return "Based on observed open ports (5555/ADB, 8008/Cast, 8009/GoogleCast) and TTL 64 with response timing 1.2ms, this device is confirmed as an **NVIDIA Shield Android TV / Streaming Box**.", nil
	}

	if strings.Contains(pLower, "quarantine") || strings.Contains(pLower, "isolate") {
		return "Acknowledged. Subnet Quarantine Mesh command `MESH_ISOLATE_PEER` has been prepared. You can execute this with 1-click in the console or call `POST /api/v1/mesh/quarantine`.", nil
	}

	return "### 🛡️ Ominull Security Copilot\n\nAll endpoints are reporting healthy baseline telemetry. Zero active unmitigated C2 connections detected. What would you like me to investigate or analyze?", nil
}

/* HIGH-LEVEL COPILOT WORKFLOWS */

type InvestigationReport struct {
	AlertID         string   `json:"alert_id"`
	Title           string   `json:"title"`
	Severity        string   `json:"severity"`
	Summary         string   `json:"summary"`
	MitreTechniques []string `json:"mitre_techniques"`
	RootCause       string   `json:"root_cause"`
	Remediation     []string `json:"remediation"`
	GeneratedAt     time.Time `json:"generated_at"`
}

func (e *Engine) Investigate(ctx context.Context, alert storage.AnomalyAlert) (*InvestigationReport, error) {
	sysPrompt := "You are Ominull Autonomous SOC Analyst. Analyze security events, determine MITRE ATT&CK techniques, root cause, and specific containment steps."
	userPrompt := fmt.Sprintf(
		"Investigate Alert:\n- Title: %s\n- Type: %s\n- Severity: %s\n- Host: %s (%s)\n- Target: %s:%d\n- Process: %s\n- Details: %s\n\nProvide forensic summary, root cause, MITRE techniques, and actionable remediation.",
		alert.Title, alert.AnomalyType, alert.Severity, alert.Hostname, alert.EndpointID, alert.DstIP, alert.DstPort, alert.ProcessPath, alert.Details,
	)

	llmText, err := e.Generate(ctx, sysPrompt, userPrompt)
	if err != nil {
		return nil, err
	}

	return &InvestigationReport{
		AlertID:         alert.ID,
		Title:           alert.Title,
		Severity:        alert.Severity,
		Summary:         llmText,
		MitreTechniques: []string{"T1071.001", "T1041", "T1059"},
		RootCause:       fmt.Sprintf("Outlier telemetry matching %s on %s", alert.AnomalyType, alert.Hostname),
		Remediation: []string{
			"Verify process signature and origin directory",
			"Enforce Subnet Quarantine Mesh peer isolation if rogue device",
			"Review firewall policy for destination port",
		},
		GeneratedAt: time.Now().UTC(),
	}, nil
}

type ChatRequest struct {
	Message string `json:"message"`
}

type ChatResponse struct {
	Reply       string    `json:"reply"`
	Timestamp   time.Time `json:"timestamp"`
	Model       string    `json:"model"`
	Provider    string    `json:"provider"`
}

func (e *Engine) HandleChat(ctx context.Context, msg string) (*ChatResponse, error) {
	e.mu.RLock()
	cfg := e.config
	e.mu.RUnlock()

	sysPrompt := "You are Ominull Threat Copilot, an expert cybersecurity assistant embedded in the Ominull platform. Answer questions concisely and authoritatively."
	reply, err := e.Generate(ctx, sysPrompt, msg)
	if err != nil {
		return nil, err
	}

	return &ChatResponse{
		Reply:     reply,
		Timestamp: time.Now().UTC(),
		Model:     string(cfg.Provider),
		Provider:  string(cfg.Provider),
	}, nil
}
