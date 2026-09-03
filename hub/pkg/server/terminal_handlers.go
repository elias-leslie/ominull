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
		id := r.URL.Query().Get("id")
		if id != "" {
			sess, err := s.terminalMgr.GetSession(id)
			if err != nil {
				writeJSONError(w, http.StatusNotFound, "session not found")
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

		s.audit(r, "TERMINAL_SESSION_CREATED", session.SessionID, fmt.Sprintf("Created shell session for %s with program %s", req.EndpointID, req.Program))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(session.Summary())
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
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

	var req struct {
		SessionID string `json:"session_id"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "operator_close"
	}

	if err := s.terminalMgr.CloseSession(req.SessionID, reason); err != nil {
		writeJSONError(w, http.StatusNotFound, "close failed: "+err.Error())
		return
	}

	s.audit(r, "TERMINAL_SESSION_CLOSED", req.SessionID, fmt.Sprintf("Closed terminal session (%s)", reason))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"closed": true})
}

// handleTerminalFrames records an input/output/resize frame for audit.
func (s *Server) handleTerminalFrames(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.terminalMgr == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "terminal manager not initialized")
		return
	}

	var req struct {
		SessionID string                 `json:"session_id"`
		Frame     terminal.TerminalFrame `json:"frame"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid frame payload")
		return
	}

	if err := s.terminalMgr.RecordFrame(req.SessionID, req.Frame); err != nil {
		writeJSONError(w, http.StatusNotFound, "failed to record frame: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"recorded": true})
}
