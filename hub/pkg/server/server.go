package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"ominull/hub/pkg/bootstrap"
	"ominull/hub/pkg/storage"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow cross-origin connection for endpoints
	},
}

type Server struct {
	store      *storage.Store
	adminKey   string
	binaryDir  string
	hubURL     string
	httpServer *http.Server

	clientsMu sync.RWMutex
	clients   map[string]*Client // endpointID -> Client
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
	return &Server{
		store:      store,
		adminKey:   adminKey,
		binaryDir:  binaryDir,
		hubURL:     hubURL,
		clients:    make(map[string]*Client),
		eventsChan: make(chan storage.Event, 1000),
	}
}

func (s *Server) Events() <-chan storage.Event {
	return s.eventsChan
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}

func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()

	// 0. Embedded Web Dashboard
	mux.HandleFunc("/", s.handleDashboard)

	// 1. Static Bootstrap & Binary Downloads
	mux.HandleFunc("/bootstrap.ps1", s.handleBootstrapPS1)
	mux.HandleFunc("/bootstrap.sh", s.handleBootstrapSH)
	mux.HandleFunc("/download/", s.handleDownload)

	// 2. Telemetry WebSocket
	mux.HandleFunc("/api/v1/ws/telemetry", s.handleWebSocket)

	// 3. Multi-Tenant REST API
	mux.HandleFunc("/api/v1/tenants", s.authMiddleware(s.handleTenants))
	mux.HandleFunc("/api/v1/endpoints", s.authMiddleware(s.handleEndpoints))
	mux.HandleFunc("/api/v1/endpoints/isolate", s.authMiddleware(s.handleIsolate))
	mux.HandleFunc("/api/v1/endpoints/unisolate", s.authMiddleware(s.handleUnisolate))
	mux.HandleFunc("/api/v1/endpoints/isolate-bulk", s.authMiddleware(s.handleBulkIsolate))
	mux.HandleFunc("/api/v1/endpoints/unisolate-bulk", s.authMiddleware(s.handleBulkUnisolate))
	mux.HandleFunc("/api/v1/events", s.authMiddleware(s.handleEvents))

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
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = r.URL.Query().Get("api_key")
		}

		if key == "" {
			http.Error(w, `{"error":"missing api key"}`, http.StatusUnauthorized)
			return
		}

		if key == s.adminKey {
			r.Header.Set("X-Role", "admin")
			next(w, r)
			return
		}

		tenant, err := s.store.GetTenantByAPIKey(key)
		if err != nil || tenant == nil {
			http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
			return
		}

		r.Header.Set("X-Role", "tenant")
		r.Header.Set("X-Tenant-ID", tenant.ID)
		next(w, r)
	}
}

func (s *Server) handleBootstrapPS1(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		key = s.adminKey
	}
	hubURL := s.hubURL
	if hubURL == "" {
		hubURL = "http://" + r.Host
	}

	script := bootstrap.GeneratePowerShell(hubURL, key)
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
		hubURL = "http://" + r.Host
	}

	script := bootstrap.GenerateBash(hubURL, key)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
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
			ip := strings.Split(r.RemoteAddr, ":")[0]
			if batch.IP != "" {
				ip = batch.IP
			}
			s.store.UpsertEndpoint(storage.Endpoint{
				ID:            batch.EndpointID,
				TenantID:      tenantID,
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
				select {
				case s.eventsChan <- batch.Events[i]:
				default:
				}
			}
			s.store.InsertEventsBatch(batch.Events)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
			return
		}

		var rawEvents []storage.Event
		if err := json.Unmarshal(bodyBytes, &rawEvents); err == nil {
			for i := range rawEvents {
				rawEvents[i].TenantID = tenantID
				if rawEvents[i].Timestamp.IsZero() {
					rawEvents[i].Timestamp = time.Now().UTC()
				}
				select {
				case s.eventsChan <- rawEvents[i]:
				default:
				}
			}
			s.store.InsertEventsBatch(rawEvents)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
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
