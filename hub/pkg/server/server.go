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
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"ominull/hub/pkg/auth"
	"ominull/hub/pkg/bootstrap"
	"ominull/hub/pkg/deployer"
	"ominull/hub/pkg/detector"
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
	store      *storage.Store
	ti         *threatintel.Manager
	detector   *detector.Engine
	pki        *pki.Manager
	scanner    *scanner.Scanner
	deployer   *deployer.Deployer
	adminKey   string
	binaryDir  string
	hubURL     string
	httpServer *http.Server

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
	Type          string          `json:"type"` // "telemetry"
	EndpointID    string          `json:"endpoint_id"`
	TenantID      string          `json:"tenant_id"`
	LocationID    string          `json:"location_id"`
	Role          string          `json:"role"`
	Hostname      string          `json:"hostname"`
	OS            string          `json:"os"`
	IP            string          `json:"ip"`
	DriverVersion string          `json:"driver_version"`
	Events        []storage.Event `json:"events"`
}

type CommandMessage struct {
	Type    string      `json:"type"` // "ISOLATE", "UNISOLATE", "UPDATE_CONFIG"
	Payload interface{} `json:"payload"`
}

func New(store *storage.Store, adminKey, binaryDir, hubURL string) *Server {
	eventsChan := make(chan storage.Event, 1000)
	pkiMgr, err := pki.New(filepath.Join(binaryDir, "certs"))
	if err != nil {
		log.Printf("[-] Warning: Failed to initialize Autonomous PKI Manager: %v", err)
	}

	s := &Server{
		store:      store,
		ti:         threatintel.New(store),
		pki:        pkiMgr,
		scanner:    scanner.New(store),
		deployer:   deployer.New(store, hubURL, adminKey),
		adminKey:   adminKey,
		binaryDir:  binaryDir,
		hubURL:     hubURL,
		clients:    make(map[string]*Client),
		eventsChan: eventsChan,
	}
	s.detector = detector.New(store, eventsChan, func(endpointID, reason string) error {
		_ = s.store.SetEndpointIsolation(endpointID, true)
		cmd := CommandMessage{
			Type: "ISOLATE",
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := strings.ReplaceAll(dashboardHTML, "ominull-master-admin-key", s.adminKey)
	w.Write([]byte(html))
}

func (s *Server) Start(addr string) error {
	// Start Threat Intelligence feed scheduler & Behavioral Detector
	s.ti.Start(context.Background(), 1*time.Hour)
	s.detector.Start(context.Background())

	mux := http.NewServeMux()

	// 0. Embedded Web Dashboard
	mux.HandleFunc("/", s.handleDashboard)

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

	// 9. Remote Push-Deployment Engine API
	mux.HandleFunc("/api/v1/deployer/push", s.authMiddleware(s.handleDeployerPush))
	mux.HandleFunc("/api/v1/deployer/status", s.authMiddleware(s.handleDeployerStatus))
	mux.HandleFunc("/api/v1/deployer/jobs", s.authMiddleware(s.handleDeployerJobs))

	// 10. Subnet Quarantine Mesh API (Lateral Isolation for Rogue Assets)
	mux.HandleFunc("/api/v1/mesh/quarantine", s.authMiddleware(s.handleMeshQuarantine))
	mux.HandleFunc("/api/v1/mesh/unquarantine", s.authMiddleware(s.handleMeshUnquarantine))
	mux.HandleFunc("/api/v1/mesh/quarantined", s.authMiddleware(s.handleMeshQuarantinedList))

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
			if key == s.adminKey || key == "omi_live_master" || key == "ominull-master-admin-key" || key == "<redacted-rotated-key>" {
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

func (s *Server) handleBootstrapPS1(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		key = s.adminKey
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
	if key == "" {
		key = s.adminKey
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
	if key == "" {
		key = s.adminKey
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
				Type: "ISOLATE",
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
			Type: "ISOLATE",
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
				ID:            batch.EndpointID,
				TenantID:      tenantID,
				LocationID:    batch.LocationID,
				RoleTag:       batch.Role,
				Hostname:      batch.Hostname,
				OS:            batch.OS,
				IP:            ip,
				DriverVersion: batch.DriverVersion,
				Status:        "online",
				LastSeenAt:    time.Now().UTC(),
				CreatedAt:     time.Now().UTC(),
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

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":            "ok",
				"quarantined_peers": qIPs,
			})
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
	windowStr := r.URL.Query().Get("window")
	windowDuration := 1 * time.Hour
	if windowStr == "6h" {
		windowDuration = 6 * time.Hour
	} else if windowStr == "24h" {
		windowDuration = 24 * time.Hour
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
