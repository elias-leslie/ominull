package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"ominull/hub/pkg/auth"
	"ominull/hub/pkg/bootstrap"
	"ominull/hub/pkg/copilot"
	"ominull/hub/pkg/deployer"
	"ominull/hub/pkg/detector"
	"ominull/hub/pkg/inference"
	"ominull/hub/pkg/pki"
	"ominull/hub/pkg/scanner"
	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow cross-origin connection for endpoints
	},
}

type Server struct {
	store        *storage.Store
	ti           *threatintel.Manager
	detector     *detector.Engine
	pki          *pki.Manager
	scanner      *scanner.Scanner
	inference    *inference.Engine
	deployer     *deployer.Deployer
	copilot      *copilot.Engine
	adminKey     string
	binaryDir    string
	hubURL       string
	agentVersion string
	httpServer   *http.Server

	clientsMu  sync.RWMutex
	clients    map[string]*Client // endpointID -> Client
	eventsChan chan storage.Event
}

type Client struct {
	EndpointID string
	TenantID   string
	Conn       *websocket.Conn
	Send       chan []byte
}

type TelemetryBatchMessage struct {
	Type       string `json:"type"` // "telemetry"
	EndpointID string `json:"endpoint_id"`
	TenantID   string `json:"tenant_id"`
	LocationID string `json:"location_id"`
	Role       string `json:"role"`
	Hostname   string `json:"hostname"`
	OS         string `json:"os"`
	IP         string `json:"ip"`
	// MAC is the endpoint's primary hardware address. Asset identity keys on
	// it, so an agented host that changes DHCP lease stays one record instead
	// of forking a second one. The Linux and macOS agents have always sent
	// this field; until 1.2.0 the hub had nowhere to put it and encoding/json
	// discarded it, which left every agented asset keyed on address alone.
	MAC           string `json:"mac"`
	DriverVersion string `json:"driver_version"`
	// UpdateCapability is the package format the agent can install for
	// itself. Deciding that from the reported OS string was always fragile -
	// that string is a display label, and v1.2.0 changed the Windows one from
	// a hardcoded literal to a detected value - so the agent states it
	// outright. Absent means "none", which is what a pre-1.3.0 agent sends.
	UpdateCapability string          `json:"update_capability"`
	Events           []storage.Event `json:"events"`
}

type CommandMessage struct {
	Type    string      `json:"type"` // "ISOLATE", "UNISOLATE", "UPDATE_CONFIG"
	Payload interface{} `json:"payload"`
}

func New(store *storage.Store, adminKey, binaryDir, hubURL, agentVersion string) *Server {
	eventsChan := make(chan storage.Event, 1000)
	pkiMgr, err := pki.New(filepath.Join(binaryDir, "certs"))
	if err != nil {
		log.Printf("[-] Warning: Failed to initialize Autonomous PKI Manager: %v", err)
	}

	// Project every existing endpoint into the asset graph before anything
	// reads it. A hub upgrading into this schema then shows its whole fleet
	// at once instead of one host per agent check-in, and the scanner's cache
	// hydrates from a populated table.
	if err := store.BackfillAssetsFromEndpoints(); err != nil {
		log.Printf("[-] Warning: Failed to backfill the asset graph from endpoints: %v", err)
	}

	s := &Server{
		store:     store,
		ti:        threatintel.New(store),
		pki:       pkiMgr,
		scanner:   scanner.New(store),
		inference: inference.New(store),
		deployer:  deployer.New(store, hubURL, adminKey),
		copilot: copilot.New(store, copilot.Config{
			Provider:    copilot.ProviderLocalOllama,
			OllamaURL:   "http://10.0.0.39:11434",
			OllamaModel: "llama3.2",
		}),
		adminKey:     adminKey,
		binaryDir:    binaryDir,
		hubURL:       hubURL,
		agentVersion: agentVersion,
		clients:      make(map[string]*Client),
		eventsChan:   eventsChan,
	}
	s.detector = detector.New(store, eventsChan, func(endpointID, reason string) error {
		_ = s.store.SetEndpointIsolation(endpointID, true)
		cmd := CommandMessage{
			Type:    "ISOLATE",
			Payload: map[string]interface{}{"reason": reason},
		}
		return s.SendCommand(endpointID, cmd)
	})
	return s
}

func (s *Server) Events() <-chan storage.Event {
	return s.eventsChan
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// Zero-Trust Least Privilege: Reject Cloudflare Service Tokens on the Web Console
	if r.Header.Get("CF-Access-Client-Id") != "" || r.Header.Get("Cf-Access-Client-Id") != "" || r.Header.Get("Cf-Access-Service-Token-Id") != "" {
		http.Error(w, "Access Denied: Service Tokens are restricted to agent telemetry and API endpoints only.", http.StatusForbidden)
		return
	}
	// The console embeds the admin API key at serve-time, so it is only rendered
	// for callers who can already present a valid admin credential.
	provided := strings.TrimSpace(r.URL.Query().Get("key"))
	if provided == "" {
		provided = strings.TrimSpace(r.Header.Get("X-API-Key"))
	}
	if provided != s.adminKey {
		if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
			if claims, err := auth.ValidateJWT(strings.TrimPrefix(authHeader, "Bearer "), s.adminKey); err == nil && claims != nil {
				provided = s.adminKey
			}
		}
	}
	if provided != s.adminKey {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(consoleGate())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(consoleDocument(s.adminKey, s.agentVersion))
}

func (s *Server) Start(addr string) error {
	// Start Threat Intelligence feed scheduler & Behavioral Detector
	s.ti.Start(context.Background(), 1*time.Hour)
	s.detector.Start(context.Background())
	// Role inference walks the whole events window, so it runs on a schedule
	// of its own rather than on any console request.
	go s.inference.Start(context.Background())

	mux := http.NewServeMux()

	// 0. Embedded operator console: the gated document at "/", plus the
	// stylesheet, script and fonts it loads. Asset paths are registered
	// individually so "/" keeps its own not-found behaviour.
	mux.HandleFunc("/", s.handleDashboard)
	for _, assetPath := range consoleAssetPaths() {
		mux.HandleFunc(assetPath, s.handleConsoleAsset)
	}

	// 1. Static Bootstrap & Binary Downloads
	mux.HandleFunc("/bootstrap.ps1", s.handleBootstrapPS1)
	mux.HandleFunc("/bootstrap.sh", s.handleBootstrapSH)
	mux.HandleFunc("/bootstrap.mac.sh", s.handleBootstrapMac)
	mux.HandleFunc("/download/", s.handleDownload)

	// 3. Multi-Tenant REST API & Hierarchy
	mux.HandleFunc("/api/v1/hierarchy", s.authMiddleware(s.handleGetHierarchy))
	mux.HandleFunc("/api/v1/locations", s.authMiddleware(s.handleLocations))
	mux.HandleFunc("/api/v1/tenants", s.authMiddleware(s.handleTenants))
	mux.HandleFunc("/api/v1/endpoints", s.authMiddleware(s.handleEndpoints))
	mux.HandleFunc("/api/v1/agent/config", s.authMiddleware(s.handleAgentConfig))
	mux.HandleFunc("/api/v1/agents/update", s.authMiddleware(s.handleAgentsUpdate))
	mux.HandleFunc("/api/v1/agents/update-status", s.authMiddleware(s.handleAgentsUpdateStatus))
	mux.HandleFunc("/api/v1/endpoints/isolate", s.authMiddleware(s.handleIsolate))
	mux.HandleFunc("/api/v1/endpoints/unisolate", s.authMiddleware(s.handleUnisolate))
	mux.HandleFunc("/api/v1/endpoints/isolate-bulk", s.authMiddleware(s.handleBulkIsolate))
	mux.HandleFunc("/api/v1/endpoints/unisolate-bulk", s.authMiddleware(s.handleBulkUnisolate))
	mux.HandleFunc("/api/v1/events", s.authMiddleware(s.handleEvents))

	// 4. Dynamic Group Policy, Exclusions & Profiling API
	mux.HandleFunc("/api/v1/network-profiles", s.authMiddleware(s.handleNetworkProfiles))
	mux.HandleFunc("/api/v1/exclusions", s.authMiddleware(s.handleExclusions))
	mux.HandleFunc("/api/v1/exclusions/toggle", s.authMiddleware(s.handleToggleExclusion))
	mux.HandleFunc("/api/v1/anomalies", s.authMiddleware(s.handleAnomalies))
	mux.HandleFunc("/api/v1/anomalies/acknowledge", s.authMiddleware(s.handleAcknowledgeAnomaly))
	mux.HandleFunc("/api/v1/policy-groups", s.authMiddleware(s.handlePolicyGroups))
	mux.HandleFunc("/api/v1/policy-groups/toggle", s.authMiddleware(s.handleTogglePolicyGroup))
	mux.HandleFunc("/api/v1/analytics/summary", s.authMiddleware(s.handleGetAnalyticsSummary))
	mux.HandleFunc("/api/v1/threatintel/iocs", s.authMiddleware(s.handleThreatIntelIOCs))
	mux.HandleFunc("/api/v1/threatintel/sync", s.authMiddleware(s.handleThreatIntelSync))
	mux.HandleFunc("/api/v1/rules", s.authMiddleware(s.handleRules))
	mux.HandleFunc("/api/v1/alerts", s.authMiddleware(s.handleAlerts))

	// 5. RBAC Auth & Audit Logging API
	mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("/api/v1/audit/logs", s.authMiddleware(s.handleAuditLogs))

	// 6. Autonomous PKI & Mutual TLS
	mux.HandleFunc("/api/v1/pki/ca.crt", s.handlePKICACert)
	mux.HandleFunc("/api/v1/pki/enroll", s.authMiddleware(s.handlePKIEnroll))

	// 7. Multi-Tier Asset Discovery & Extensible Scanner API
	mux.HandleFunc("/api/v1/scanner/scan", s.authMiddleware(s.handleScannerScan))
	mux.HandleFunc("/api/v1/scanner/status", s.authMiddleware(s.handleScannerStatus))
	mux.HandleFunc("/api/v1/scanner/results", s.authMiddleware(s.handleScannerResults))
	mux.HandleFunc("/api/v1/scanner/coverage", s.authMiddleware(s.handleScannerCoverage))
	mux.HandleFunc("/api/v1/scanner/feedback", s.authMiddleware(s.handleScannerFeedback))

	// 8. Visual Communications Topology Graph API
	mux.HandleFunc("/api/v1/topology/graph", s.authMiddleware(s.handleTopologyGraph))

	// 8b. Unified asset graph and flow inference
	mux.HandleFunc("/api/v1/assets", s.authMiddleware(s.handleAssets))
	mux.HandleFunc("/api/v1/assets/correct", s.authMiddleware(s.handleAssetCorrect))
	mux.HandleFunc("/api/v1/inference/status", s.authMiddleware(s.handleInferenceStatus))
	mux.HandleFunc("/api/v1/inference/run", s.authMiddleware(s.handleInferenceRun))

	// 9. Remote Push-Deployment Engine API
	mux.HandleFunc("/api/v1/deployer/push", s.authMiddleware(s.handleDeployerPush))
	mux.HandleFunc("/api/v1/deployer/status", s.authMiddleware(s.handleDeployerStatus))
	mux.HandleFunc("/api/v1/deployer/jobs", s.authMiddleware(s.handleDeployerJobs))

	// 10. Subnet Quarantine Mesh API (Lateral Isolation for Rogue Assets)
	mux.HandleFunc("/api/v1/mesh/quarantine", s.authMiddleware(s.handleMeshQuarantine))
	mux.HandleFunc("/api/v1/mesh/unquarantine", s.authMiddleware(s.handleMeshUnquarantine))
	mux.HandleFunc("/api/v1/mesh/quarantined", s.authMiddleware(s.handleMeshQuarantinedList))

	// 11. Autonomous Security Copilot API
	mux.HandleFunc("/api/v1/copilot/chat", s.authMiddleware(s.handleCopilotChat))
	mux.HandleFunc("/api/v1/copilot/investigate", s.authMiddleware(s.handleCopilotInvestigate))
	mux.HandleFunc("/api/v1/copilot/config", s.authMiddleware(s.handleCopilotConfig))

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("[+] Ominull Hub listening on %s (Admin Key configured)", addr)
	return s.httpServer.ListenAndServe()
}

func (s *Server) Close() error {
	s.ti.Stop()
	s.detector.Stop()
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. Check Bearer JWT Token
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := auth.ValidateJWT(tokenStr, s.adminKey)
			if err == nil && claims != nil {
				r.Header.Set("X-Role", claims.Role)
				r.Header.Set("X-User-ID", claims.UserID)
				r.Header.Set("X-Username", claims.Username)
				if claims.TenantID != "" {
					r.Header.Set("X-Tenant-ID", claims.TenantID)
				}
				next(w, r)
				return
			}
		}

		// 2. Check X-API-Key Header and Query Param
		keys := []string{
			strings.TrimSpace(r.Header.Get("X-API-Key")),
			strings.TrimSpace(r.URL.Query().Get("api_key")),
		}

		for _, key := range keys {
			if key == "" {
				continue
			}
			if key == s.adminKey {
				r.Header.Set("X-Role", "admin")
				r.Header.Set("X-Username", "admin")
				next(w, r)
				return
			}
			tenant, err := s.store.GetTenantByAPIKey(key)
			if err == nil && tenant != nil {
				r.Header.Set("X-Role", "tenant")
				r.Header.Set("X-Tenant-ID", tenant.ID)
				r.Header.Set("X-Username", tenant.Name)
				next(w, r)
				return
			}
		}

		http.Error(w, `{"error":"invalid or missing api key"}`, http.StatusUnauthorized)
		return
	}
}

// versionParts extracts the leading major.minor.patch triple from a reported version
// string. Endpoints decorate the version with an engine suffix ("1.1.0 (WFP Callout)",
// "1.1.0 (eBPF/TC)"), so each component is read up to its first non-digit.
func versionParts(v string) [3]int {
	var out [3]int
	fields := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	for i := 0; i < 3 && i < len(fields); i++ {
		digits := strings.TrimSpace(fields[i])
		end := 0
		for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
			end++
		}
		out[i], _ = strconv.Atoi(digits[:end])
	}
	return out
}

// compareVersions compares dotted numeric versions: -1 if a < b, 0 if equal, 1 if a > b.
func compareVersions(a, b string) int {
	as, bs := versionParts(a), versionParts(b)
	for i := 0; i < 3; i++ {
		if as[i] != bs[i] {
			if as[i] < bs[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// desiredAgentVersion resolves the fleet-wide target agent version: the operator-set
// value if present, otherwise the version bundled with this hub build.
func (s *Server) desiredAgentVersion() string {
	if v, _ := s.store.GetSetting("desired_agent_version"); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return s.agentVersion
}

// downloadBase is the URL prefix agents fetch packages from.
func (s *Server) downloadBase(r *http.Request) string {
	baseURL := strings.TrimSuffix(s.hubURL, "/")
	if baseURL == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		}
		baseURL = scheme + "://" + r.Host
	}
	return baseURL
}

// agentPackageName is the on-disk filename of an agent package. Signature and
// digest sidecars hang off it, so name resolution has exactly one home.
func agentPackageName(version, pkg string) string {
	switch pkg {
	case "windows":
		return "ominull-agent-windows-" + version + ".tar.gz"
	case "macos":
		return "ominull-agent-macos-" + version + ".tar.gz"
	default:
		return "ominull-agent_" + version + "_amd64.deb"
	}
}

// agentPackageURL builds the download URL for an agent package of the given version.
func (s *Server) agentPackageURL(r *http.Request, version, pkg string) string {
	return s.downloadBase(r) + "/download/" + agentPackageName(version, pkg)
}

// agentUpdateDescriptor assembles everything an agent needs to fetch a release
// and prove it is genuine before installing it.
//
// It fails closed. Both the digest and the detached signature must be on disk
// beside the package or no descriptor is produced at all. Agents verify against
// a public key compiled into them rather than anything the hub serves, so an
// unsigned release is one every agent would refuse anyway; advertising it just
// turns a release mistake into a fleet of failed downloads. Catching it here
// means an unsigned release shows up as "not offered" in one place instead of
// as an install failure on every endpoint.
func (s *Server) agentUpdateDescriptor(r *http.Request, version, pkg string) (map[string]string, bool) {
	name := agentPackageName(version, pkg)
	if _, err := os.Stat(filepath.Join(s.binaryDir, name)); err != nil {
		return nil, false
	}
	raw, err := os.ReadFile(filepath.Join(s.binaryDir, name+".sha256"))
	if err != nil {
		return nil, false
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 || len(fields[0]) != 64 {
		return nil, false
	}
	if _, err := os.Stat(filepath.Join(s.binaryDir, name+".sig")); err != nil {
		return nil, false
	}
	base := s.downloadBase(r)
	return map[string]string{
		"version":   version,
		"package":   pkg,
		"url":       base + "/download/" + name,
		"signature": base + "/download/" + name + ".sig",
		"sha256":    fields[0],
	}, true
}

// agentPackageForCapability maps what an agent says it can install onto the
// package the hub serves. An agent that claims nothing is offered nothing.
func agentPackageForCapability(capability string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(capability)) {
	case "deb":
		return "deb", true
	case "pkg":
		return "macos", true
	case "exe":
		return "windows", true
	}
	return "", false
}

// updatePackageFor resolves the package an endpoint can install for itself.
//
// The reported capability is authoritative. An endpoint that has never
// reported one is running an agent from before the field existed, and the only
// such agent that can install anything is the Linux one - so the legacy
// fallback covers precisely that case and nothing else. A pre-1.3.0 Windows or
// macOS agent cannot act on a descriptor at all, and is honestly reported as
// needing the push-deployer rather than handed a package it will ignore.
func updatePackageFor(capability, osName string) (string, bool) {
	if pkg, ok := agentPackageForCapability(capability); ok {
		return pkg, true
	}
	if strings.TrimSpace(capability) == "" && agentPackageKind(osName) == "deb" && strings.Contains(strings.ToLower(osName), "linux") {
		return "deb", true
	}
	return "", false
}

// agentPackageKind maps a reported OS string onto the packaging flavour the hub serves.
func agentPackageKind(osName string) string {
	lower := strings.ToLower(osName)
	switch {
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "darwin"), strings.Contains(lower, "mac"):
		return "macos"
	default:
		return "deb"
	}
}

// pendingAgentUpdate resolves the update an endpoint should apply given the version it
// just reported. It also retires any queued job the endpoint has already satisfied, so
// the agent reporting its new version is what closes the loop on an update.
func (s *Server) pendingAgentUpdate(endpointID, reportedVersion string) (string, bool) {
	target := s.desiredAgentVersion()
	job, _ := s.store.GetAgentUpdateJob(endpointID)
	if job != nil && job.CompletedAt == nil {
		if compareVersions(job.DesiredVersion, target) > 0 {
			target = job.DesiredVersion
		}
		if compareVersions(reportedVersion, job.DesiredVersion) >= 0 {
			s.store.CompleteAgentUpdate(endpointID)
		}
	}
	return target, compareVersions(reportedVersion, target) < 0
}

// handleAgentConfig is the agent-facing configuration poll. Agents call it with their
// endpoint_id; if the hub has queued an update job (or a fleet-wide desired version)
// newer than the agent's reported version, the response carries the update package URL.
func (s *Server) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	endpointID := strings.TrimSpace(r.URL.Query().Get("endpoint_id"))
	if endpointID == "" {
		http.Error(w, `{"error":"endpoint_id is required"}`, http.StatusBadRequest)
		return
	}
	ep, err := s.store.GetEndpoint(endpointID)
	if err != nil || ep == nil {
		http.Error(w, `{"error":"endpoint not registered"}`, http.StatusNotFound)
		return
	}

	reported := ep.DriverVersion
	if v := strings.TrimSpace(r.URL.Query().Get("version")); v != "" {
		reported = v
	}
	desired, outdated := s.pendingAgentUpdate(endpointID, reported)

	resp := map[string]interface{}{
		"endpoint_id":      ep.ID,
		"agent_version":    reported,
		"latest_version":   desired,
		"update_available": outdated,
	}
	if outdated {
		pkg, selfInstallable := updatePackageFor(ep.UpdateCapability, ep.OS)
		if !selfInstallable {
			pkg = agentPackageKind(ep.OS)
		}
		resp["update_version"] = desired
		resp["package"] = pkg
		resp["update_url"] = s.agentPackageURL(r, desired, pkg)
		if desc, signed := s.agentUpdateDescriptor(r, desired, pkg); signed {
			resp["sha256"] = desc["sha256"]
			resp["signature_url"] = desc["signature"]
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleAgentsUpdate lets an operator push a new agent version to endpoints.
// Endpoints that report an update capability self-update over their existing hub
// connection; the rest are reported back as requiring the SSH/WinRM push-deployer.
func (s *Server) handleAgentsUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Role") != "admin" {
		http.Error(w, `{"error":"admin role required"}`, http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		EndpointIDs []string `json:"endpoint_ids"`
		All         bool     `json:"all"`
		Version     string   `json:"version"`
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, `{"error":"invalid json body"}`, http.StatusBadRequest)
		return
	}

	version := strings.TrimSpace(req.Version)
	if version == "" {
		version = s.desiredAgentVersion()
	}
	if compareVersions(s.agentVersion, version) > 0 {
		http.Error(w, `{"error":"refusing to downgrade: hub bundle ships agent `+s.agentVersion+`"}`, http.StatusBadRequest)
		return
	}
	if err := s.store.SetSetting("desired_agent_version", version); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	endpoints, err := s.store.ListEndpoints("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var scheduled, unsupported []map[string]string
	for _, ep := range endpoints {
		if !req.All && !contains(req.EndpointIDs, ep.ID) {
			continue
		}
		if compareVersions(ep.DriverVersion, version) >= 0 {
			continue // already up to date
		}
		pkg, selfInstallable := updatePackageFor(ep.UpdateCapability, ep.OS)
		if !selfInstallable {
			unsupported = append(unsupported, map[string]string{"endpoint_id": ep.ID, "hostname": ep.Hostname, "os": ep.OS, "reason": "endpoint reports no self-update capability; use the SSH/WinRM push-deployer"})
			continue
		}
		// Refuse to queue a job for a release the endpoint could never install.
		// The agent verifies the signature itself and would reject it, so an
		// unsigned release must surface here as one clear answer rather than as
		// a queued job that quietly never completes.
		if _, signed := s.agentUpdateDescriptor(r, version, pkg); !signed {
			unsupported = append(unsupported, map[string]string{"endpoint_id": ep.ID, "hostname": ep.Hostname, "os": ep.OS, "reason": "no signed " + agentPackageName(version, pkg) + " on the hub; sign the release with scripts/sign-release.sh and redeploy"})
			continue
		}
		if err := s.store.RequestAgentUpdate(ep.ID, version); err == nil {
			scheduled = append(scheduled, map[string]string{"endpoint_id": ep.ID, "hostname": ep.Hostname, "from": ep.DriverVersion, "to": version})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"desired_version": version,
		"scheduled":       scheduled,
		"unsupported":     unsupported,
	})
}

// handleAgentsUpdateStatus reports fleet agent-version currency and pending update jobs.
func (s *Server) handleAgentsUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	latest := s.desiredAgentVersion()
	endpoints, err := s.store.ListEndpoints("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var outdated []map[string]string
	for _, ep := range endpoints {
		if compareVersions(ep.DriverVersion, latest) < 0 {
			outdated = append(outdated, map[string]string{
				"endpoint_id":    ep.ID,
				"hostname":       ep.Hostname,
				"os":             ep.OS,
				"ip":             ep.IP,
				"driver_version": ep.DriverVersion,
			})
		}
	}
	pending, _ := s.store.ListPendingAgentUpdates()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"latest_version": latest,
		"outdated":       outdated,
		"pending":        pending,
	})
}

func contains(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

func (s *Server) handleBootstrapPS1(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" || key != s.adminKey {
		http.Error(w, `{"error":"valid admin key required"}`, http.StatusUnauthorized)
		return
	}
	hubURL := s.hubURL
	if hubURL == "" {
		hubURL = "https://" + r.Host
	}

	cfID := r.URL.Query().Get("cf_id")
	if cfID == "" {
		cfID = r.Header.Get("CF-Access-Client-Id")
	}
	cfSecret := r.URL.Query().Get("cf_secret")
	if cfSecret == "" {
		cfSecret = r.Header.Get("CF-Access-Client-Secret")
	}
	locationID := r.URL.Query().Get("location")
	roleTag := r.URL.Query().Get("role")

	script := bootstrap.GeneratePowerShell(hubURL, key, cfID, cfSecret, locationID, roleTag)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

func (s *Server) handleBootstrapSH(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" || key != s.adminKey {
		http.Error(w, `{"error":"valid admin key required"}`, http.StatusUnauthorized)
		return
	}
	hubURL := s.hubURL
	if hubURL == "" {
		hubURL = "https://" + r.Host
	}

	cfID := r.URL.Query().Get("cf_id")
	if cfID == "" {
		cfID = r.Header.Get("CF-Access-Client-Id")
	}
	cfSecret := r.URL.Query().Get("cf_secret")
	if cfSecret == "" {
		cfSecret = r.Header.Get("CF-Access-Client-Secret")
	}
	locationID := r.URL.Query().Get("location")
	roleTag := r.URL.Query().Get("role")

	script := bootstrap.GenerateBash(hubURL, key, cfID, cfSecret, locationID, roleTag)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

func (s *Server) handleBootstrapMac(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" || key != s.adminKey {
		http.Error(w, `{"error":"valid admin key required"}`, http.StatusUnauthorized)
		return
	}
	hubURL := s.hubURL
	if hubURL == "" {
		hubURL = "https://" + r.Host
	}

	cfID := r.URL.Query().Get("cf_id")
	if cfID == "" {
		cfID = r.Header.Get("CF-Access-Client-Id")
	}
	cfSecret := r.URL.Query().Get("cf_secret")
	if cfSecret == "" {
		cfSecret = r.Header.Get("CF-Access-Client-Secret")
	}
	locationID := r.URL.Query().Get("location")
	roleTag := r.URL.Query().Get("role")

	script := bootstrap.GenerateMacOS(hubURL, key, cfID, cfSecret, locationID, roleTag)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

func (s *Server) handlePKICACert(w http.ResponseWriter, r *http.Request) {
	if s.pki == nil {
		http.Error(w, "PKI not initialized", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ca.crt\"")
	w.Write(s.pki.GetCAPEM())
}

func (s *Server) handlePKIEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.pki == nil {
		http.Error(w, "PKI not initialized", http.StatusInternalServerError)
		return
	}

	var req struct {
		Hostname string `json:"hostname"`
		IP       string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Hostname == "" {
		req.Hostname = "ominull-endpoint"
	}

	bundle, err := s.pki.IssueClientCert(req.Hostname, req.IP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bundle)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	filename := strings.TrimPrefix(r.URL.Path, "/download/")
	filename = filepath.Base(filename)

	path := filepath.Join(s.binaryDir, filename)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	http.ServeFile(w, r, path)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	apiKey := r.URL.Query().Get("key")
	if apiKey == "" {
		apiKey = r.Header.Get("X-API-Key")
	}

	var tenantID string
	if apiKey == s.adminKey {
		tenantID = "admin-tenant"
	} else {
		t, err := s.store.GetTenantByAPIKey(apiKey)
		if err != nil || t == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tenantID = t.ID
	}

	endpointID := r.URL.Query().Get("endpoint_id")
	if endpointID == "" {
		endpointID = uuid.New().String()
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[-] WebSocket upgrade failed: %v", err)
		return
	}

	client := &Client{
		EndpointID: endpointID,
		TenantID:   tenantID,
		Conn:       conn,
		Send:       make(chan []byte, 256),
	}

	s.clientsMu.Lock()
	s.clients[endpointID] = client
	s.clientsMu.Unlock()

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, endpointID)
		s.clientsMu.Unlock()
		conn.Close()

		s.store.UpsertEndpoint(storage.Endpoint{
			ID:         endpointID,
			TenantID:   tenantID,
			Status:     "offline",
			LastSeenAt: time.Now().UTC(),
		})
	}()

	// Reader Loop
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var batch TelemetryBatchMessage
		if err := json.Unmarshal(message, &batch); err != nil {
			continue
		}

		if batch.Type == "telemetry" {
			// Update endpoint record
			s.store.UpsertEndpoint(storage.Endpoint{
				ID:            endpointID,
				TenantID:      tenantID,
				Hostname:      batch.Hostname,
				OS:            batch.OS,
				IP:            batch.IP,
				DriverVersion: batch.DriverVersion,
				Status:        "online",
				LastSeenAt:    time.Now().UTC(),
				CreatedAt:     time.Now().UTC(),
			})

			// Save batch events
			for i := range batch.Events {
				batch.Events[i].TenantID = tenantID
				batch.Events[i].EndpointID = endpointID
				if batch.Events[i].Timestamp.IsZero() {
					batch.Events[i].Timestamp = time.Now().UTC()
				}
				select {
				case s.eventsChan <- batch.Events[i]:
				default:
				}
			}
			s.store.InsertEventsBatch(batch.Events)
		}
	}
}

func (s *Server) SendCommand(endpointID string, cmd CommandMessage) error {
	s.clientsMu.RLock()
	client, ok := s.clients[endpointID]
	s.clientsMu.RUnlock()

	if !ok {
		return fmt.Errorf("endpoint %s is offline or disconnected", endpointID)
	}

	data, err := json.Marshal(cmd)
	if err != nil {
		return err
	}

	return client.Conn.WriteMessage(websocket.TextMessage, data)
}

func (s *Server) handleTenants(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		list, err := s.store.ListTenants()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
		return
	}

	if r.Method == http.MethodPost {
		var t storage.Tenant
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if t.ID == "" {
			t.ID = "tenant-" + uuid.New().String()[:8]
		}
		if t.APIKey == "" {
			t.APIKey = "ominull_key_" + uuid.New().String()
		}
		t.CreatedAt = time.Now().UTC()

		if err := s.store.CreateTenant(t); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(t)
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	list, err := s.store.ListEndpoints(tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.clientsMu.RLock()
	for i := range list {
		_, wsOnline := s.clients[list[i].ID]
		if wsOnline || time.Since(list[i].LastSeenAt) < 30*time.Second {
			list[i].Status = "online"
		} else {
			list[i].Status = "offline"
		}
	}
	s.clientsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func (s *Server) handleIsolate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		EndpointID string   `json:"endpoint_id"`
		AllowIPs   []string `json:"allow_ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cmd := CommandMessage{
		Type: "ISOLATE",
		Payload: map[string]interface{}{
			"allow_ips": req.AllowIPs,
		},
	}

	_ = s.SendCommand(req.EndpointID, cmd)

	s.store.SetEndpointIsolation(req.EndpointID, true)

	_ = s.store.RecordAudit(storage.AuditEntry{
		ID:        uuid.New().String(),
		TenantID:  r.Header.Get("X-Tenant-ID"),
		UserID:    r.Header.Get("X-User-ID"),
		Username:  r.Header.Get("X-Username"),
		Action:    "ISOLATE_HOST",
		Resource:  req.EndpointID,
		Details:   "Host network isolation enabled at ring-0",
		IPAddress: strings.Split(r.RemoteAddr, ":")[0],
		Timestamp: time.Now().UTC(),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"isolated","endpoint_id":"` + req.EndpointID + `"}`))
}

func (s *Server) handleUnisolate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		EndpointID string `json:"endpoint_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cmd := CommandMessage{
		Type: "UNISOLATE",
	}

	_ = s.SendCommand(req.EndpointID, cmd)

	s.store.SetEndpointIsolation(req.EndpointID, false)

	_ = s.store.RecordAudit(storage.AuditEntry{
		ID:        uuid.New().String(),
		TenantID:  r.Header.Get("X-Tenant-ID"),
		UserID:    r.Header.Get("X-User-ID"),
		Username:  r.Header.Get("X-Username"),
		Action:    "UNISOLATE_HOST",
		Resource:  req.EndpointID,
		Details:   "Host network isolation lifted",
		IPAddress: strings.Split(r.RemoteAddr, ":")[0],
		Timestamp: time.Now().UTC(),
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"unisolated","endpoint_id":"` + req.EndpointID + `"}`))
}

func (s *Server) handleBulkIsolate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	var req struct {
		Scope    string   `json:"scope"`
		Value    string   `json:"value"`
		IDs      []string `json:"ids"`
		AllowIPs []string `json:"allow_ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Scope == "" {
		req.Scope = "all"
	}

	var count int64
	if req.Scope == "ids" && len(req.IDs) > 0 {
		for _, id := range req.IDs {
			s.store.SetEndpointIsolation(id, true)
			cmd := CommandMessage{
				Type:    "ISOLATE",
				Payload: map[string]interface{}{"allow_ips": req.AllowIPs},
			}
			_ = s.SendCommand(id, cmd)
			count++
		}
	} else {
		var err error
		count, err = s.store.SetBulkIsolation(tenantID, req.Scope, req.Value, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		cmd := CommandMessage{
			Type:    "ISOLATE",
			Payload: map[string]interface{}{"allow_ips": req.AllowIPs},
		}
		s.clientsMu.RLock()
		for id := range s.clients {
			_ = s.SendCommand(id, cmd)
		}
		s.clientsMu.RUnlock()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             "isolated",
		"affected_endpoints": count,
		"scope":              req.Scope,
		"value":              req.Value,
	})
}

func (s *Server) handleBulkUnisolate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	var req struct {
		Scope string   `json:"scope"`
		Value string   `json:"value"`
		IDs   []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Scope == "" {
		req.Scope = "all"
	}

	var count int64
	if req.Scope == "ids" && len(req.IDs) > 0 {
		for _, id := range req.IDs {
			s.store.SetEndpointIsolation(id, false)
			cmd := CommandMessage{Type: "UNISOLATE"}
			_ = s.SendCommand(id, cmd)
			count++
		}
	} else {
		var err error
		count, err = s.store.SetBulkIsolation(tenantID, req.Scope, req.Value, false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		cmd := CommandMessage{Type: "UNISOLATE"}
		s.clientsMu.RLock()
		for id := range s.clients {
			_ = s.SendCommand(id, cmd)
		}
		s.clientsMu.RUnlock()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             "unisolated",
		"affected_endpoints": count,
		"scope":              req.Scope,
		"value":              req.Value,
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	tenantID := "default"
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	if r.Method == http.MethodPost {
		var batch TelemetryBatchMessage
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := json.Unmarshal(bodyBytes, &batch); err == nil && batch.EndpointID != "" {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}
			if batch.IP != "" {
				ip = batch.IP
			}
			s.store.UpsertEndpoint(storage.Endpoint{
				ID:               batch.EndpointID,
				TenantID:         tenantID,
				LocationID:       batch.LocationID,
				RoleTag:          batch.Role,
				Hostname:         batch.Hostname,
				OS:               batch.OS,
				IP:               ip,
				MAC:              batch.MAC,
				DriverVersion:    batch.DriverVersion,
				UpdateCapability: batch.UpdateCapability,
				Status:           "online",
				LastSeenAt:       time.Now().UTC(),
				CreatedAt:        time.Now().UTC(),
			})

			for i := range batch.Events {
				batch.Events[i].TenantID = tenantID
				batch.Events[i].EndpointID = batch.EndpointID
				if batch.Events[i].Timestamp.IsZero() {
					batch.Events[i].Timestamp = time.Now().UTC()
				}

				// Enrich with in-flight GeoIP & ASN resolution
				geo := threatintel.ResolveGeoIP(batch.Events[i].DstIP)
				if batch.Events[i].Country == "" || batch.Events[i].Country == "US" {
					batch.Events[i].Country = geo.Country
				}

				// Match against Threat Intelligence Cache
				if ioc, found := s.ti.CheckThreat(batch.Events[i].DstIP); found {
					batch.Events[i].Action = "BLOCK"
					log.Printf("[!] THREAT MATCH: Endpoint %s -> C2 IP %s blocked (Source: %s, Threat: %s, Confidence: %d%%)",
						batch.EndpointID, batch.Events[i].DstIP, ioc.Source, ioc.ThreatType, ioc.Confidence)
				} else if ioc, found := s.ti.CheckThreat(batch.Events[i].SrcIP); found {
					batch.Events[i].Action = "BLOCK"
					log.Printf("[!] THREAT MATCH: Inbound threat %s blocked on %s (Source: %s, Threat: %s)",
						batch.Events[i].SrcIP, batch.EndpointID, ioc.Source, ioc.ThreatType)
				}

				// Evaluate against anomaly detection & comms profiling
				s.detector.Evaluate(batch.Events[i])
			}
			s.store.InsertEventsBatch(batch.Events)

			qPeers, _ := s.store.GetQuarantinedPeers()
			qIPs := make([]string, 0, len(qPeers))
			for _, p := range qPeers {
				if p.Active {
					qIPs = append(qIPs, p.TargetIP)
				}
			}

			resp := map[string]interface{}{
				"status":            "ok",
				"quarantined_peers": qIPs,
			}
			if target, outdated := s.pendingAgentUpdate(batch.EndpointID, batch.DriverVersion); outdated {
				if pkg, ok := updatePackageFor(batch.UpdateCapability, batch.OS); ok {
					if desc, signed := s.agentUpdateDescriptor(r, target, pkg); signed {
						resp["agent_update"] = desc
					}
				}
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
			return
		}

		var rawEvents []storage.Event
		if err := json.Unmarshal(bodyBytes, &rawEvents); err == nil {
			for i := range rawEvents {
				rawEvents[i].TenantID = tenantID
				if rawEvents[i].Timestamp.IsZero() {
					rawEvents[i].Timestamp = time.Now().UTC()
				}

				geo := threatintel.ResolveGeoIP(rawEvents[i].DstIP)
				if rawEvents[i].Country == "" || rawEvents[i].Country == "US" {
					rawEvents[i].Country = geo.Country
				}

				if ioc, found := s.ti.CheckThreat(rawEvents[i].DstIP); found {
					rawEvents[i].Action = "BLOCK"
					log.Printf("[!] THREAT MATCH: Connection to C2 IP %s blocked (Source: %s, Threat: %s)",
						rawEvents[i].DstIP, ioc.Source, ioc.ThreatType)
				}

				// Evaluate against anomaly detection & comms profiling
				s.detector.Evaluate(rawEvents[i])
			}
			s.store.InsertEventsBatch(rawEvents)

			qPeers, _ := s.store.GetQuarantinedPeers()
			qIPs := make([]string, 0, len(qPeers))
			for _, p := range qPeers {
				if p.Active {
					qIPs = append(qIPs, p.TargetIP)
				}
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":            "ok",
				"quarantined_peers": qIPs,
			})
			return
		}

		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	endpointID := r.URL.Query().Get("endpoint_id")
	events, err := s.store.QueryEvents(tenantID, endpointID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (s *Server) handleThreatIntelIOCs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	iocs, err := s.store.ListIOCs(200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(iocs)
}

func (s *Server) handleThreatIntelSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	go func() {
		_ = s.ti.SyncAllFeeds(context.Background())
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"syncing","message":"Threat intelligence synchronization initiated in background"}`))
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	tenantID := "default"
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	if r.Method == http.MethodPost {
		var req struct {
			Name       string `json:"name"`
			Type       string `json:"type"` // "ip", "cidr", "domain", "process", "port"
			Value      string `json:"value"`
			Port       uint16 `json:"port"`
			Protocol   string `json:"protocol"`
			Action     string `json:"action"` // "BLOCK", "PERMIT"
			Scope      string `json:"scope"`
			ScopeValue string `json:"scope_value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Action == "" {
			req.Action = "BLOCK"
		}
		if req.Protocol == "" {
			req.Protocol = "any"
		}
		if req.Scope == "" {
			req.Scope = "all"
		}

		rule := storage.Rule{
			ID:         uuid.New().String(),
			TenantID:   tenantID,
			Name:       req.Name,
			Type:       req.Type,
			Value:      req.Value,
			Port:       req.Port,
			Protocol:   req.Protocol,
			Action:     req.Action,
			Scope:      req.Scope,
			ScopeValue: req.ScopeValue,
			Active:     true,
			CreatedAt:  time.Now().UTC(),
		}

		if err := s.store.CreateRule(rule); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Broadcast rule update to connected endpoints
		cmd := CommandMessage{
			Type: "UPDATE_CONFIG",
			Payload: map[string]interface{}{
				"rule": rule,
			},
		}
		s.clientsMu.RLock()
		for id := range s.clients {
			_ = s.SendCommand(id, cmd)
		}
		s.clientsMu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(rule)
		return
	}

	if r.Method == http.MethodGet {
		rules, err := s.store.ListRules(tenantID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rules)
		return
	}

	if r.Method == http.MethodDelete {
		ruleID := r.URL.Query().Get("id")
		if ruleID == "" {
			http.Error(w, "missing rule id", http.StatusBadRequest)
			return
		}
		if err := s.store.DeleteRule(ruleID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"deleted","rule_id":"` + ruleID + `"}`))
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := "default"
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	alerts, err := s.store.ListAlerts(tenantID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Username == "admin" && req.Password == s.adminKey {
		token, err := auth.GenerateJWT(auth.Claims{
			UserID:   "usr-admin",
			Username: "admin",
			Role:     auth.RoleAdmin,
			TenantID: "default",
		}, s.adminKey, 24*time.Hour)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_ = s.store.RecordAudit(storage.AuditEntry{
			ID:        uuid.New().String(),
			TenantID:  "default",
			UserID:    "usr-admin",
			Username:  "admin",
			Action:    "LOGIN",
			Resource:  "auth",
			Details:   "Admin user logged in via master key",
			IPAddress: strings.Split(r.RemoteAddr, ":")[0],
			Timestamp: time.Now().UTC(),
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "authenticated",
			"token":  token,
			"role":   auth.RoleAdmin,
		})
		return
	}

	http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	logs, err := s.store.ListAuditLogs(tenantID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func (s *Server) handleGetHierarchy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	tree, err := s.store.GetHierarchy(tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tree)
}

func (s *Server) handleLocations(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	switch r.Method {
	case http.MethodGet:
		locs, err := s.store.ListLocations(tenantID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(locs)

	case http.MethodPost:
		var loc storage.Location
		if err := json.NewDecoder(r.Body).Decode(&loc); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if loc.ID == "" {
			loc.ID = "loc-" + uuid.New().String()[:8]
		}
		if loc.TenantID == "" {
			loc.TenantID = "default"
		}
		if role == "tenant" {
			loc.TenantID = r.Header.Get("X-Tenant-ID")
		}
		loc.CreatedAt = time.Now().UTC()

		if err := s.store.CreateLocation(loc); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(loc)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePolicyGroups(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	switch r.Method {
	case http.MethodGet:
		groups, err := s.store.ListPolicyGroups(tenantID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(groups)

	case http.MethodPost:
		var g storage.PolicyGroup
		if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if g.ID == "" {
			g.ID = "grp-" + uuid.New().String()[:8]
		}
		if g.TenantID == "" {
			g.TenantID = "default"
		}
		if role == "tenant" {
			g.TenantID = r.Header.Get("X-Tenant-ID")
		}
		if g.Criteria == "" {
			g.Criteria = "{}"
		}
		g.Active = true
		g.CreatedAt = time.Now().UTC()

		if err := s.store.CreatePolicyGroup(g); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Broadcast to matching connected endpoints
		cmd := CommandMessage{
			Type: "ADD_RULE",
			Payload: map[string]interface{}{
				"id":       g.ID,
				"name":     g.Name,
				"type":     g.RuleType,
				"value":    g.RuleValue,
				"port":     g.Port,
				"protocol": g.Protocol,
				"action":   g.Action,
			},
		}
		s.clientsMu.RLock()
		for epID := range s.clients {
			_ = s.SendCommand(epID, cmd)
		}
		s.clientsMu.RUnlock()

		_ = s.store.RecordAudit(storage.AuditEntry{
			ID:        uuid.New().String(),
			TenantID:  g.TenantID,
			UserID:    r.Header.Get("X-User-ID"),
			Username:  r.Header.Get("X-Username"),
			Action:    "CREATE_POLICY_GROUP",
			Resource:  g.ID,
			Details:   fmt.Sprintf("Created group policy: %s (Action: %s)", g.Name, g.Action),
			IPAddress: strings.Split(r.RemoteAddr, ":")[0],
			Timestamp: time.Now().UTC(),
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(g)

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		if err := s.store.DeletePolicyGroup(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"deleted","id":"` + id + `"}`))

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTogglePolicyGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID     string `json:"id"`
		Active bool   `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.TogglePolicyGroup(req.ID, req.Active); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "updated", "id": req.ID, "active": req.Active})
}

func (s *Server) handleGetAnalyticsSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	summary, err := s.store.GetAnalyticsSummary(tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

func (s *Server) handleNetworkProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	level := r.URL.Query().Get("level") // "global", "client", "location", "endpoint"
	id := r.URL.Query().Get("id")

	role := r.Header.Get("X-Role")
	if role == "tenant" {
		level = "client"
		id = r.Header.Get("X-Tenant-ID")
	}

	profiles, err := s.store.ListCommProfiles(level, id, 250)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profiles)
}

func (s *Server) handleExclusions(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	switch r.Method {
	case http.MethodGet:
		exclusions, err := s.store.ListExclusions(tenantID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(exclusions)

	case http.MethodPost:
		var ex storage.Exclusion
		if err := json.NewDecoder(r.Body).Decode(&ex); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if ex.ID == "" {
			ex.ID = "ex-" + uuid.New().String()[:8]
		}
		if ex.TenantID == "" {
			ex.TenantID = "default"
		}
		if role == "tenant" {
			ex.TenantID = r.Header.Get("X-Tenant-ID")
		}
		if ex.Scope == "" {
			ex.Scope = "global"
		}
		ex.Active = true
		ex.CreatedAt = time.Now().UTC()

		if err := s.store.CreateExclusion(ex); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Broadcast pinhole allowlist command to connected endpoints
		cmd := CommandMessage{
			Type: "ADD_RULE",
			Payload: map[string]interface{}{
				"id":       ex.ID,
				"name":     ex.Name,
				"type":     "ip",
				"value":    ex.DstIPRange,
				"port":     ex.Port,
				"protocol": ex.Protocol,
				"action":   "PERMIT",
			},
		}
		s.clientsMu.RLock()
		for epID := range s.clients {
			_ = s.SendCommand(epID, cmd)
		}
		s.clientsMu.RUnlock()

		_ = s.store.RecordAudit(storage.AuditEntry{
			ID:        uuid.New().String(),
			TenantID:  ex.TenantID,
			UserID:    r.Header.Get("X-User-ID"),
			Username:  r.Header.Get("X-Username"),
			Action:    "CREATE_EXCLUSION",
			Resource:  ex.ID,
			Details:   fmt.Sprintf("Created security tool exclusion: %s (%s:%d)", ex.Name, ex.ProcessPath, ex.Port),
			IPAddress: strings.Split(r.RemoteAddr, ":")[0],
			Timestamp: time.Now().UTC(),
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ex)

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		if err := s.store.DeleteExclusion(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"deleted","id":"` + id + `"}`))

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleToggleExclusion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID     string `json:"id"`
		Active bool   `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.ToggleExclusion(req.ID, req.Active); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "updated", "id": req.ID, "active": req.Active})
}

func (s *Server) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	role := r.Header.Get("X-Role")
	tenantID := ""
	if role == "tenant" {
		tenantID = r.Header.Get("X-Tenant-ID")
	}

	anomalies, err := s.store.ListAnomalyAlerts(tenantID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(anomalies)
}

func (s *Server) handleAcknowledgeAnomaly(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.AcknowledgeAnomaly(req.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "acknowledged", "id": req.ID})
}

/* 7. NETWORK ASSET DISCOVERY & EXTENSIBLE SCANNER HANDLERS */

func (s *Server) handleScannerScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Subnet  string `json:"subnet"`
		Profile string `json:"profile"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Subnet == "" {
		req.Subnet = "10.0.0.0/24"
	}
	prof := scanner.ScanProfile(req.Profile)
	if prof == "" {
		prof = scanner.ProfileStandard
	}

	scanID, err := s.scanner.StartScan(req.Subnet, prof)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id": scanID,
		"subnet":  req.Subnet,
		"profile": prof,
		"status":  "running",
	})
}

func (s *Server) handleScannerStatus(w http.ResponseWriter, r *http.Request) {
	scanID := r.URL.Query().Get("id")
	if scanID == "" {
		http.Error(w, "missing scan id", http.StatusBadRequest)
		return
	}
	st, err := s.scanner.GetScanStatus(scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(st)
}

func (s *Server) handleScannerResults(w http.ResponseWriter, r *http.Request) {
	assets := s.scanner.GetDiscoveredAssets()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assets)
}

func (s *Server) handleScannerCoverage(w http.ResponseWriter, r *http.Request) {
	cov := s.scanner.GetCoverageSummary()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cov)
}

func (s *Server) handleScannerFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		IP           string `json:"ip"`
		ActualDevice string `json:"actual_device"`
		Vendor       string `json:"vendor"`
		Category     string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.IP == "" || req.ActualDevice == "" {
		http.Error(w, "missing ip or actual_device", http.StatusBadRequest)
		return
	}

	sig, err := s.scanner.TrainSignature(req.IP, req.ActualDevice, req.Vendor, req.Category)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "trained",
		"signature": sig,
	})
}

/* 8. VISUAL COMMUNICATIONS TOPOLOGY GRAPH HANDLER */

func (s *Server) handleTopologyGraph(w http.ResponseWriter, r *http.Request) {
	// Default 24h, not 1h: a known asset that was quiet in the last hour is
	// still on the network, and the graph draws it dimmed rather than
	// pretending it does not exist.
	windowStr := r.URL.Query().Get("window")
	windowDuration := 24 * time.Hour
	if windowStr == "1h" {
		windowDuration = 1 * time.Hour
	} else if windowStr == "6h" {
		windowDuration = 6 * time.Hour
	} else if windowStr == "7d" {
		windowDuration = 7 * 24 * time.Hour
	}

	topoData, err := s.store.GetTopologyGraph(windowDuration)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topoData)
}

/* 8b. UNIFIED ASSET GRAPH + FLOW INFERENCE HANDLERS */

// handleAssets returns the whole asset graph: one row per host, however many
// sources know about it, with every source's claim attached so the console can
// show the losing opinions next to the winning one.
func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	assets, err := s.store.ListAssets(r.URL.Query().Get("tenant_id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assets)
}

// handleAssetCorrect records an operator's verdict on a field, or withdraws
// one. A correction outranks every other source permanently, and where it
// corrects a device identity it is also fed back into the scanner's signature
// set so the next probe of a similar host gets it right unaided.
func (s *Server) handleAssetCorrect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AssetID  string `json:"asset_id"`
		IP       string `json:"ip"`
		Field    string `json:"field"`
		Value    string `json:"value"`
		Reason   string `json:"reason"`
		Withdraw bool   `json:"withdraw"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Field == "" {
		http.Error(w, "missing field", http.StatusBadRequest)
		return
	}

	key := req.AssetID
	if key == "" {
		key = req.IP
	}
	asset, err := s.store.GetAsset(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if req.Withdraw {
		if err := s.store.DropClaim(asset.ID, req.Field, storage.SourceOperator); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if req.Value == "" {
			http.Error(w, "missing value", http.StatusBadRequest)
			return
		}
		if err := s.store.CorrectAsset(asset.ID, req.Field, req.Value, req.Reason); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Feed signature training: an operator naming what a device actually
		// is teaches the fingerprinter, not just this one row.
		if req.Field == storage.FieldCategory && asset.IP != "" {
			if _, err := s.scanner.TrainSignature(asset.IP, req.Value, asset.Vendor, req.Value); err != nil {
				log.Printf("[*] Correction on %s not fed to signature training: %v", asset.IP, err)
			}
		}
	}

	action := "CORRECT_ASSET"
	if req.Withdraw {
		action = "WITHDRAW_CORRECTION"
	}
	_ = s.store.RecordAudit(storage.AuditEntry{
		ID:        uuid.NewString(),
		TenantID:  asset.TenantID,
		UserID:    "admin",
		Username:  "admin",
		Action:    action,
		Resource:  asset.ID,
		Details:   req.Field + " = " + req.Value,
		IPAddress: strings.Split(r.RemoteAddr, ":")[0],
		Timestamp: time.Now().UTC(),
	})

	updated, err := s.store.GetAsset(asset.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

func (s *Server) handleInferenceStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.inference.Status())
}

// handleInferenceRun triggers a pass out of schedule. Inference is scheduled
// work; this exists so an operator who just onboarded a subnet does not wait
// for the next tick.
func (s *Server) handleInferenceRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	n, err := s.inference.RunOnce()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":         "completed",
		"inferred_count": n,
		"detail":         s.inference.Status(),
	})
}

/* 9. REMOTE PUSH-DEPLOYMENT ENGINE HANDLERS */

func (s *Server) handleDeployerPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req deployer.DeployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	jobID, err := s.deployer.DispatchPush(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"job_id":    jobID,
		"target_ip": req.TargetIP,
		"status":    "running",
	})
}

func (s *Server) handleDeployerStatus(w http.ResponseWriter, r *http.Request) {
	jobID := r.URL.Query().Get("id")
	if jobID == "" {
		http.Error(w, "missing job id", http.StatusBadRequest)
		return
	}
	st, err := s.deployer.GetJobStatus(jobID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(st)
}

func (s *Server) handleDeployerJobs(w http.ResponseWriter, r *http.Request) {
	jobs := s.deployer.ListJobs()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jobs)
}

/* 10. SUBNET QUARANTINE MESH HANDLERS */

type MeshQuarantineRequest struct {
	TargetIP  string `json:"target_ip"`
	TargetMAC string `json:"target_mac"`
	Subnet    string `json:"subnet"`
	Reason    string `json:"reason"`
}

func (s *Server) handleMeshQuarantine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req MeshQuarantineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TargetIP == "" {
		http.Error(w, "invalid request: target_ip is required", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		req.Reason = "Unmanaged/rogue lateral threat quarantine"
	}

	peer, err := s.store.AddQuarantinedPeer(req.TargetIP, req.TargetMAC, req.Subnet, req.Reason)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Broadcast MESH_ISOLATE_PEER command to all connected agents
	cmd := CommandMessage{
		Type: "MESH_ISOLATE_PEER",
		Payload: map[string]interface{}{
			"target_ip":  req.TargetIP,
			"target_mac": req.TargetMAC,
			"action":     "BLOCK",
			"reason":     req.Reason,
		},
	}
	s.clientsMu.RLock()
	for id := range s.clients {
		_ = s.SendCommand(id, cmd)
	}
	s.clientsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "quarantined",
		"peer":   peer,
	})
}

func (s *Server) handleMeshUnquarantine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req MeshQuarantineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TargetIP == "" {
		http.Error(w, "invalid request: target_ip is required", http.StatusBadRequest)
		return
	}

	if err := s.store.RemoveQuarantinedPeer(req.TargetIP); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cmd := CommandMessage{
		Type: "MESH_ISOLATE_PEER",
		Payload: map[string]interface{}{
			"target_ip": req.TargetIP,
			"action":    "ALLOW",
		},
	}
	s.clientsMu.RLock()
	for id := range s.clients {
		_ = s.SendCommand(id, cmd)
	}
	s.clientsMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "unquarantined",
		"target_ip": req.TargetIP,
	})
}

func (s *Server) handleMeshQuarantinedList(w http.ResponseWriter, r *http.Request) {
	peers, err := s.store.GetQuarantinedPeers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

/* 11. AUTONOMOUS SECURITY COPILOT HANDLERS */

func (s *Server) handleCopilotChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req copilot.ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Message) == "" {
		http.Error(w, "invalid request: message is required", http.StatusBadRequest)
		return
	}

	resp, err := s.copilot.HandleChat(r.Context(), req.Message)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleCopilotInvestigate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AlertID string `json:"alert_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AlertID == "" {
		http.Error(w, "invalid request: alert_id is required", http.StatusBadRequest)
		return
	}

	anomalies, err := s.store.ListAnomalyAlerts("default", 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var targetAlert *storage.AnomalyAlert
	for _, a := range anomalies {
		if a.ID == req.AlertID {
			targetAlert = &a
			break
		}
	}
	if targetAlert == nil {
		http.Error(w, "alert not found", http.StatusNotFound)
		return
	}

	report, err := s.copilot.Investigate(r.Context(), *targetAlert)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

func (s *Server) handleCopilotConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.copilot.GetConfig())
		return
	}
	if r.Method == http.MethodPost {
		var cfg copilot.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.copilot.UpdateConfig(cfg)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.copilot.GetConfig())
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
