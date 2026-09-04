package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/terminal"
)

// handleTerminalSessions handles creating, listing, and showing terminal sessions.
func (s *Server) handleTerminalSessions(w http.ResponseWriter, r *http.Request) {
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}

	if r.Method == http.MethodGet {
		if r.Header.Get("X-Auth-Method") == "api-key" {
			writeJSONError(w, http.StatusForbidden, "static API keys cannot list or inspect terminal sessions")
			return
		}
		role := r.Header.Get("X-Role")
		if role != "admin" && role != "operator" && role != "auditor" {
			writeJSONError(w, http.StatusForbidden, "unauthorized role for terminal session inspection")
			return
		}

		id := r.URL.Query().Get("id")
		if id != "" {
			sess, err := s.terminalMgr.GetSession(id)
			if err != nil {
				writeJSONError(w, http.StatusNotFound, "session not found")
				return
			}
			if sess.TenantID != tenantID {
				writeJSONError(w, http.StatusForbidden, "session belongs to different tenant")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sess.Summary())
			return
		}

		sessions := s.terminalMgr.ListSessions(tenantID)
		var summaries []map[string]interface{}
		for _, sess := range sessions {
			summaries = append(summaries, sess.Summary())
		}
		if summaries == nil {
			summaries = []map[string]interface{}{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"sessions": summaries,
		})
		return
	}

	if r.Method == http.MethodPost {
		if r.Header.Get("X-Auth-Method") == "api-key" {
			writeJSONError(w, http.StatusForbidden, "static API keys cannot create terminal sessions; response authorization required")
			return
		}

		var req struct {
			EndpointID   string                    `json:"endpoint_id"`
			Program      string                    `json:"program"` // /bin/sh, /bin/bash, powershell.exe, cmd.exe
			SessionID    string                    `json:"session_id"`
			ActionDigest string                    `json:"action_digest"`
			Proof        *responseauth.ActionProof `json:"proof"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}

		if req.EndpointID == "" {
			writeJSONError(w, http.StatusBadRequest, "missing endpoint_id")
			return
		}
		if req.Program == "" {
			req.Program = "/bin/bash"
		}

		operatorID := s.operatorFromRequest(r)

		payload := response.TerminalSessionPayload{
			Program: req.Program,
		}
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to marshal terminal payload: "+err.Error())
			return
		}
		computedDigest := sha256.Sum256(payloadBytes)
		computedDigestHex := hex.EncodeToString(computedDigest[:])

		if req.ActionDigest != "" && !strings.EqualFold(req.ActionDigest, computedDigestHex) {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("action digest mismatch: client supplied %s but recomputed payload digest is %s", req.ActionDigest, computedDigestHex))
			return
		}
		if req.Proof != nil && req.Proof.ActionDigest != "" && !strings.EqualFold(req.Proof.ActionDigest, computedDigestHex) {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("proof action digest mismatch: proof binds to %s but recomputed payload digest is %s", req.Proof.ActionDigest, computedDigestHex))
			return
		}

		if s.responseAuth == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "response authority not available")
			return
		}

		// Validate proof and sign EndpointGrant
		grant, err := s.responseAuth.SignGrant(r.Context(), &responseauth.SignGrantRequest{
			TenantID:      tenantID,
			OperatorID:    operatorID,
			SessionID:     req.SessionID,
			EndpointID:    req.EndpointID,
			ActionKind:    response.ActionKindTerminalSession,
			ActionDigest:  computedDigestHex,
			ActionPayload: json.RawMessage(payloadBytes),
			TTLSeconds:    300,
			Proof:         req.Proof,
		})
		if err != nil {
			writeJSONError(w, http.StatusForbidden, "response authority denied shell grant: "+err.Error())
			return
		}

		session, err := s.terminalMgr.CreateSession(tenantID, req.EndpointID, operatorID, req.Program, grant)
		if err != nil {
			writeJSONError(w, http.StatusConflict, "failed to create terminal session: "+err.Error())
			return
		}

		// Also create a durable response job so the endpoint receives the offer in next heartbeat
		payloadJSON := fmt.Sprintf(`{"session_id":%q,"program":%q,"connect_token":%q}`, session.SessionID, session.Program, session.ConnectToken)
		if s.responseStore != nil {
			_, _ = s.responseStore.CreateJob(tenantID, req.EndpointID, response.ActionKindTerminalSession, operatorID, grant, payloadJSON, "")
		}

		// Set one-use HttpOnly attach cookie for the operator browser on this origin
		http.SetCookie(w, &http.Cookie{
			Name:     "ominull_terminal_token",
			Value:    session.ConnectToken,
			Path:     "/api/v1/terminal/ws/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   300,
		})

		s.audit(r, "TERMINAL_SESSION_CREATED", session.SessionID, fmt.Sprintf("Created shell session for %s with program %s", req.EndpointID, req.Program))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(session.Summary())
		return
	}

	if r.Method == http.MethodDelete {
		if r.Header.Get("X-Auth-Method") == "api-key" {
			writeJSONError(w, http.StatusForbidden, "static API keys cannot close terminal sessions")
			return
		}
		role := r.Header.Get("X-Role")
		if role != "admin" && role != "operator" {
			writeJSONError(w, http.StatusForbidden, "insufficient role permissions to close terminal session")
			return
		}

		id := r.URL.Query().Get("id")
		if id == "" {
			writeJSONError(w, http.StatusBadRequest, "missing session id")
			return
		}

		sess, err := s.terminalMgr.GetSession(id)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "session not found")
			return
		}
		if sess.TenantID != tenantID {
			writeJSONError(w, http.StatusForbidden, "session belongs to different tenant")
			return
		}

		if err := s.terminalMgr.CloseSession(id, "operator_closed"); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to close session: "+err.Error())
			return
		}

		s.audit(r, "TERMINAL_SESSION_CLOSED", id, fmt.Sprintf("Operator closed terminal session %s", id))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "closed", "session_id": id})
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// handleTerminalWSOperator handles WebSocket connections from the console operator.
func (s *Server) handleTerminalWSOperator(w http.ResponseWriter, r *http.Request) {
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.Header.Get("X-Terminal-Token")
	}
	if token == "" {
		if cookie, err := r.Cookie("ominull_terminal_token"); err == nil {
			token = cookie.Value
		}
	}

	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "missing terminal token")
		return
	}

	if err := s.terminalMgr.AttachOperator(w, r, sessionID, token); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "terminal attachment rejected: "+err.Error())
		return
	}
}

// handleTerminalWSAgent handles WebSocket connections from the remote endpoint agent.
func (s *Server) handleTerminalWSAgent(w http.ResponseWriter, r *http.Request) {
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return
	}

	endpointID := r.URL.Query().Get("endpoint_id")
	if endpointID == "" {
		endpointID = strings.TrimSpace(r.Header.Get("X-Device-Endpoint-ID"))
	}
	if endpointID == "" {
		endpointID = strings.TrimSpace(r.Header.Get("X-Client-CN"))
	}
	if endpointID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing endpoint_id")
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.Header.Get("X-Terminal-Token")
	}
	if token == "" {
		writeJSONError(w, http.StatusUnauthorized, "missing terminal token")
		return
	}

	if err := s.terminalMgr.AttachAgent(w, r, sessionID, endpointID, token); err != nil {
		writeJSONError(w, http.StatusUnauthorized, "terminal attachment rejected: "+err.Error())
		return
	}
}

// handleTerminalSessionClose handles closing a terminal session.
func (s *Server) handleTerminalSessionClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}

	if r.Header.Get("X-Auth-Method") == "api-key" {
		writeJSONError(w, http.StatusForbidden, "static API keys cannot close terminal sessions")
		return
	}

	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	role := r.Header.Get("X-Role")
	if role != "admin" && role != "operator" {
		writeJSONError(w, http.StatusForbidden, "insufficient role permissions to close terminal session")
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return
	}

	sess, err := s.terminalMgr.GetSession(req.SessionID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "session not found")
		return
	}
	if sess.TenantID != tenantID {
		writeJSONError(w, http.StatusForbidden, "session belongs to different tenant")
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "operator_close"
	}

	if err := s.terminalMgr.CloseSession(req.SessionID, reason); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "close failed: "+err.Error())
		return
	}

	s.audit(r, "TERMINAL_SESSION_CLOSED", req.SessionID, fmt.Sprintf("Closed terminal session (%s)", reason))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"closed": true, "session_id": req.SessionID})
}

// handleTerminalFrames inspects recorded frames or rejects external frame injection.
func (s *Server) handleTerminalFrames(w http.ResponseWriter, r *http.Request) {
	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}

	if r.Method == http.MethodGet {
		if r.Header.Get("X-Auth-Method") == "api-key" {
			writeJSONError(w, http.StatusForbidden, "static API keys cannot inspect terminal frames")
			return
		}

		role := r.Header.Get("X-Role")
		if role != "admin" && role != "operator" && role != "auditor" {
			writeJSONError(w, http.StatusForbidden, "unauthorized role for terminal frame inspection")
			return
		}

		tenantID := s.tenantFromRequest(r)
		if tenantID == "" {
			tenantID = "default"
		}

		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			sessionID = r.URL.Query().Get("id")
		}
		if sessionID == "" {
			writeJSONError(w, http.StatusBadRequest, "missing session_id")
			return
		}

		frames, meta, err := s.terminalMgr.GetSessionRecording(tenantID, sessionID)
		if err != nil {
			if strings.Contains(err.Error(), "tenant mismatch") {
				writeJSONError(w, http.StatusForbidden, "session belongs to different tenant")
				return
			}
			if strings.Contains(err.Error(), "not found") {
				writeJSONError(w, http.StatusNotFound, "session not found")
				return
			}
			writeJSONError(w, http.StatusInternalServerError, "failed to read recording: "+err.Error())
			return
		}

		if frames == nil {
			frames = []terminal.TerminalFrame{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"metadata": meta,
			"frames":   frames,
		})
		return
	}

	if r.Method == http.MethodPost {
		writeJSONError(w, http.StatusForbidden, "external frame injection rejected: frames must stream over authenticated websocket relay")
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}
