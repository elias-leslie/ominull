package responseauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Server exposes the Authority over HTTP on a Unix domain socket.
type Server struct {
	auth       *Authority
	httpServer *http.Server
	listener   net.Listener
	socketPath string
}

// NewServer creates a new Response Authority HTTP server over a Unix socket or net.Listener.
func NewServer(auth *Authority, socketPath string) (*Server, error) {
	if auth == nil {
		return nil, errors.New("nil authority")
	}

	mux := http.NewServeMux()
	s := &Server{
		auth:       auth,
		socketPath: socketPath,
	}

	mux.HandleFunc("/v1/auth/tenant-key", s.handleTenantKey)
	mux.HandleFunc("/v1/auth/totp/enroll", s.handleTOTPEnroll)
	mux.HandleFunc("/v1/auth/session/unlock", s.handleSessionUnlock)
	mux.HandleFunc("/v1/auth/session/lock", s.handleSessionLock)
	mux.HandleFunc("/v1/auth/grant/sign", s.handleSignGrant)
	mux.HandleFunc("/v1/auth/recovery/generate", s.handleGenerateRecovery)
	mux.HandleFunc("/v1/auth/status", s.handleStatus)

	s.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return s, nil
}

// Start listens on the configured Unix socket path.
func (s *Server) Start() error {
	if s.socketPath == "" {
		return errors.New("empty socket path")
	}

	_ = os.Remove(s.socketPath)
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0755); err != nil {
		return err
	}

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket %s: %w", s.socketPath, err)
	}
	s.listener = l
	_ = os.Chmod(s.socketPath, 0660)

	go func() {
		_ = s.httpServer.Serve(l)
	}()
	return nil
}

// Close stops the server and cleans up the socket.
func (s *Server) Close() error {
	var err error
	if s.httpServer != nil {
		err = s.httpServer.Shutdown(context.Background())
	}
	if s.socketPath != "" {
		_ = os.Remove(s.socketPath)
	}
	return err
}

func (s *Server) handleTenantKey(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		http.Error(w, `{"error":"missing tenant_id"}`, http.StatusBadRequest)
		return
	}
	pub, keyID, err := s.auth.GetOrCreateTenantKey(tenantID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"tenant_id":  tenantID,
		"public_key": fmt.Sprintf("%x", pub),
		"key_id":     keyID,
	})
}

func (s *Server) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		TenantID   string `json:"tenant_id"`
		OperatorID string `json:"operator_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	secret, err := s.auth.EnrollTOTP(req.TenantID, req.OperatorID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"secret": secret,
	})
}

func (s *Server) handleSessionUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		TenantID         string `json:"tenant_id"`
		OperatorID       string `json:"operator_id"`
		BrowserSessionID string `json:"browser_session_id"`
		BrowserPublicKey string `json:"browser_public_key"`
		TOTPCode         string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	session, err := s.auth.UnlockSessionWithTOTP(req.TenantID, req.OperatorID, req.BrowserSessionID, req.BrowserPublicKey, req.TOTPCode)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(session)
}

func (s *Server) handleSessionLock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if err := s.auth.LockSession(req.SessionID); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"locked": true})
}

func (s *Server) handleSignGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req SignGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	grant, err := s.auth.SignGrant(&req)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(SignGrantResponse{Grant: grant})
}

func (s *Server) handleGenerateRecovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		TenantID   string `json:"tenant_id"`
		OperatorID string `json:"operator_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	token, err := s.auth.GenerateRecoveryToken(req.TenantID, req.OperatorID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	status := s.auth.Status(tenantID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
