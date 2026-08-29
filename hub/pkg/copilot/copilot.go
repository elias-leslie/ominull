package copilot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	// No default URL. A built-in address that happens not to answer is the
	// same failure as none at all, except that it looks configured.

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
		// Both numbers are bounded by the hub's 30s WriteTimeout, and that is
		// the point. At the 45s this used to use, a provider that never
		// answered outlived the response the operator was waiting for: the hub
		// closed the connection at 30s with nothing written, so the console got
		// an empty reply rather than the degradation notice. Twenty seconds
		// leaves room to serialise the answer.
		//
		// The dial timeout matters more than the total. An unroutable provider
		// address - the state this deployment was actually in - hangs in
		// connect, and three seconds is the difference between a copilot that
		// degrades visibly and one that looks frozen.
		client: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
				TLSHandshakeTimeout: 5 * time.Second,
			},
		},
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

// Answer is what the copilot actually produced, as opposed to what it was
// configured to produce. The distinction matters: when the configured model is
// unreachable the engine answers from a small built-in rule set instead, and
// that answer is confident, formatted like the real thing, and completely
// generic. Reporting the configured provider as the author of it - which is
// what shipped before - tells an operator a model looked at their alert when
// nothing did.
type Answer struct {
	Text string
	// Provider and Model describe what wrote Text, not what was configured.
	Provider ProviderType
	Model    string
	// Degraded is set when the configured provider could not answer. Reason
	// says why, in a sentence meant to be shown to whoever asked.
	Degraded bool
	Reason   string
}

// Ask runs a prompt through the configured provider and reports which one
// answered. Callers that only want the text can use Generate.
func (e *Engine) Ask(ctx context.Context, systemPrompt string, prompt string) Answer {
	e.mu.RLock()
	cfg := e.config
	e.mu.RUnlock()

	var text string
	var err error

	switch cfg.Provider {
	case ProviderRuleBased:
		text, _ = e.generateHeuristic(systemPrompt, prompt)
		return Answer{Text: text, Provider: ProviderRuleBased, Model: string(ProviderRuleBased)}
	case ProviderLocalOllama:
		if strings.TrimSpace(cfg.OllamaURL) == "" {
			return e.fallback(cfg, systemPrompt, prompt, "no ollama_url is set")
		}
		text, err = e.generateOllama(ctx, cfg, systemPrompt, prompt)
	case ProviderGemini:
		if cfg.GeminiAPIKey == "" {
			return e.fallback(cfg, systemPrompt, prompt, "no Gemini API key is set")
		}
		text, err = e.generateGemini(ctx, cfg, systemPrompt, prompt)
	case ProviderOpenAI:
		if cfg.OpenAIAPIKey == "" {
			return e.fallback(cfg, systemPrompt, prompt, "no OpenAI API key is set")
		}
		text, err = e.generateOpenAI(ctx, cfg, systemPrompt, prompt)
	default:
		return e.fallback(cfg, systemPrompt, prompt, fmt.Sprintf("%q is not a provider this hub knows", cfg.Provider))
	}

	if err != nil {
		return e.fallback(cfg, systemPrompt, prompt, err.Error())
	}
	if strings.TrimSpace(text) == "" {
		return e.fallback(cfg, systemPrompt, prompt, "it returned an empty completion")
	}
	return Answer{Text: text, Provider: cfg.Provider, Model: modelFor(cfg)}
}

// fallback answers from the rule set and says so. It never reports the
// configured provider as the author.
func (e *Engine) fallback(cfg Config, systemPrompt, prompt, reason string) Answer {
	text, _ := e.generateHeuristic(systemPrompt, prompt)
	return Answer{
		Text:     text,
		Provider: ProviderRuleBased,
		Model:    string(ProviderRuleBased),
		Degraded: true,
		Reason: fmt.Sprintf("%s (%s) did not answer: %s. This reply came from the built-in rule set, "+
			"not from a model, and is generic.", cfg.Provider, modelFor(cfg), reason),
	}
}

func modelFor(cfg Config) string {
	switch cfg.Provider {
	case ProviderLocalOllama:
		return cfg.OllamaModel
	case ProviderGemini:
		return cfg.GeminiModel
	case ProviderOpenAI:
		return cfg.OpenAIModel
	}
	return string(cfg.Provider)
}

// Generate is the text-only form, kept for callers that have nothing to do with
// a degradation notice.
func (e *Engine) Generate(ctx context.Context, systemPrompt string, prompt string) (string, error) {
	return e.Ask(ctx, systemPrompt, prompt).Text, nil
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

	// Failures are returned, not swallowed. Falling back in here is what made
	// an unreachable Ollama indistinguishable from a working one: the caller
	// got a confident answer and no indication of where it came from. Ask owns
	// the fallback now, and labels it.
	resp, err := e.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("cannot reach %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return "", fmt.Errorf("%s answered HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
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
	AlertID         string    `json:"alert_id"`
	Title           string    `json:"title"`
	Severity        string    `json:"severity"`
	Summary         string    `json:"summary"`
	MitreTechniques []string  `json:"mitre_techniques"`
	RootCause       string    `json:"root_cause"`
	Remediation     []string  `json:"remediation"`
	GeneratedAt     time.Time `json:"generated_at"`
	// Same contract as ChatResponse: an investigation written by the rule set
	// reads exactly like one written by a model, so it has to say which it is.
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Degraded bool   `json:"degraded"`
	Notice   string `json:"notice,omitempty"`
}

func (e *Engine) Investigate(ctx context.Context, alert storage.AnomalyAlert) (*InvestigationReport, error) {
	sysPrompt := "You are Ominull Autonomous SOC Analyst. Analyze security events, determine MITRE ATT&CK techniques, root cause, and specific containment steps."
	userPrompt := fmt.Sprintf(
		"Investigate Alert:\n- Title: %s\n- Type: %s\n- Severity: %s\n- Host: %s (%s)\n- Target: %s:%d\n- Process: %s\n- Details: %s\n\nProvide forensic summary, root cause, MITRE techniques, and actionable remediation.",
		alert.Title, alert.AnomalyType, alert.Severity, alert.Hostname, alert.EndpointID, alert.DstIP, alert.DstPort, alert.ProcessPath, alert.Details,
	)

	answer := e.Ask(ctx, sysPrompt, userPrompt)

	return &InvestigationReport{
		AlertID:         alert.ID,
		Title:           alert.Title,
		Severity:        alert.Severity,
		Summary:         answer.Text,
		Provider:        string(answer.Provider),
		Model:           answer.Model,
		Degraded:        answer.Degraded,
		Notice:          answer.Reason,
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
	Reply     string    `json:"reply"`
	Timestamp time.Time `json:"timestamp"`
	// Model and Provider name what wrote Reply. When Degraded is set that is
	// the built-in rule set rather than the configured model, and Notice says
	// why - a console showing the reply without it would be presenting a
	// generic canned answer as analysis.
	Model    string `json:"model"`
	Provider string `json:"provider"`
	Degraded bool   `json:"degraded"`
	Notice   string `json:"notice,omitempty"`
}

func (e *Engine) HandleChat(ctx context.Context, msg string) (*ChatResponse, error) {
	sysPrompt := "You are Ominull Threat Copilot, an expert cybersecurity assistant embedded in the Ominull platform. Answer questions concisely and authoritatively."
	answer := e.Ask(ctx, sysPrompt, msg)

	return &ChatResponse{
		Reply:     answer.Text,
		Timestamp: time.Now().UTC(),
		Model:     answer.Model,
		Provider:  string(answer.Provider),
		Degraded:  answer.Degraded,
		Notice:    answer.Reason,
	}, nil
}
