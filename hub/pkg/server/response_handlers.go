package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
)

// handleResponseJobs handles listing and creating response jobs.
func (s *Server) handleResponseJobs(w http.ResponseWriter, r *http.Request) {
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	if r.Method == http.MethodGet {
		endpointID := r.URL.Query().Get("endpoint_id")
		limit := 50
		if qLimit := r.URL.Query().Get("limit"); qLimit != "" {
			if n, err := strconv.Atoi(qLimit); err == nil && n > 0 && n <= 100 {
				limit = n
			}
		}

		if s.responseStore == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "response engine not initialized")
			return
		}

		jobs, err := s.responseStore.ListJobs(tenantID, endpointID, limit)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to list jobs: "+err.Error())
			return
		}
		if jobs == nil {
			jobs = []*response.JobRecord{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jobs":  jobs,
			"count": len(jobs),
		})
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			EndpointID     string              `json:"endpoint_id"`
			Kind           response.ActionKind `json:"kind"`
			PayloadJSON    string              `json:"payload_json"`
			IdempotencyKey string              `json:"idempotency_key"`
			SessionID      string              `json:"session_id"`
			ActionDigest   string              `json:"action_digest"`
			Proof          *responseauth.ActionProof `json:"proof"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request json: "+err.Error())
			return
		}

		if req.EndpointID == "" || req.Kind == "" || req.PayloadJSON == "" {
			writeJSONError(w, http.StatusBadRequest, "missing endpoint_id, kind, or payload_json")
			return
		}

		operatorID := s.operatorFromRequest(r)

		// Independently recompute canonical SHA-256 action digest from payload
		hasher := sha256.New()
		hasher.Write([]byte(req.PayloadJSON))
		computedDigestHex := hex.EncodeToString(hasher.Sum(nil))

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

		// Request grant signing from Response Authority
		grant, err := s.responseAuth.SignGrant(r.Context(), &responseauth.SignGrantRequest{
			TenantID:      tenantID,
			OperatorID:    operatorID,
			SessionID:     req.SessionID,
			EndpointID:    req.EndpointID,
			ActionKind:    req.Kind,
			ActionDigest:  computedDigestHex,
			ActionPayload: json.RawMessage(req.PayloadJSON),
			TTLSeconds:    300,
			Proof:         req.Proof,
		})
		if err != nil {
			writeJSONError(w, http.StatusForbidden, "response authority denied grant: "+err.Error())
			return
		}

		job, err := s.responseStore.CreateJob(tenantID, req.EndpointID, req.Kind, operatorID, grant, req.PayloadJSON, req.IdempotencyKey)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to create response job: "+err.Error())
			return
		}

		s.audit(r, "RESPONSE_JOB_CREATED", req.EndpointID, fmt.Sprintf("Created %s response job %s", req.Kind, job.ID))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(job)
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// handleResponseJobsCancel handles cancellation requests for jobs.
func (s *Server) handleResponseJobsCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		JobID string `json:"job_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.JobID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing job_id")
		return
	}

	operatorID := s.operatorFromRequest(r)

	if s.responseStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response engine not initialized")
		return
	}

	tenantID := s.tenantFromRequest(r)
	if err := s.responseStore.CancelJob(tenantID, req.JobID, operatorID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to cancel job: "+err.Error())
		return
	}

	s.audit(r, "RESPONSE_JOB_CANCELLED", req.JobID, fmt.Sprintf("Cancelled response job %s", req.JobID))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "cancel_requested", "job_id": req.JobID})
}

// handleResponseAck handles endpoint job acknowledgment.
func (s *Server) handleResponseAck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var ack response.JobAck
	if err := json.NewDecoder(r.Body).Decode(&ack); err != nil || ack.JobID == "" || ack.LeaseID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid ack payload")
		return
	}

	if s.responseStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response store not initialized")
		return
	}

	tenantID := s.tenantFromRequest(r)
	endpointID := r.Header.Get("X-Client-CN")
	if endpointID == "" {
		endpointID = r.Header.Get("X-Device-Endpoint-ID")
	}

	if err := s.responseStore.AcknowledgeJob(tenantID, endpointID, ack.JobID, ack.LeaseID, ack.Accepted, ack.RejectionReason); err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to record ack: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleResponseResult handles endpoint job final result reporting.
func (s *Server) handleResponseResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var res response.JobResult
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil || res.JobID == "" || res.LeaseID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid result payload")
		return
	}

	if s.responseStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response store not initialized")
		return
	}

	tenantID := s.tenantFromRequest(r)
	endpointID := r.Header.Get("X-Client-CN")
	if endpointID == "" {
		endpointID = r.Header.Get("X-Device-Endpoint-ID")
	}

	if err := s.responseStore.CompleteJob(tenantID, endpointID, res.JobID, res.LeaseID, &res); err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to record result: "+err.Error())
		return
	}

	s.audit(r, "RESPONSE_JOB_COMPLETED", res.JobID, fmt.Sprintf("Completed response job %s state=%s exit_code=%d", res.JobID, res.State, res.ExitCode))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleResponseAuthTOTPEnroll handles enrolling a TOTP secret.
func (s *Server) handleResponseAuthTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	operatorID := s.operatorFromRequest(r)
	var req struct {
		OperatorID string `json:"operator_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.OperatorID != "" && r.Header.Get("X-Role") == "admin" {
		operatorID = req.OperatorID
	}

	if s.responseAuth == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response authority not available")
		return
	}

	secret, err := s.responseAuth.EnrollTOTP(r.Context(), tenantID, operatorID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to enroll totp: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"secret": secret,
		"otpauth_url": fmt.Sprintf("otpauth://totp/Ominull:%s@%s?secret=%s&issuer=Ominull", operatorID, tenantID, secret),
	})
}

// handleResponseAuthUnlock handles unlocking a response session.
func (s *Server) handleResponseAuthUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	var req struct {
		OperatorID       string `json:"operator_id"`
		BrowserSessionID string `json:"browser_session_id"`
		BrowserPublicKey string `json:"browser_public_key"`
		TOTPCode         string `json:"totp_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request json: "+err.Error())
		return
	}
	if req.OperatorID == "" {
		req.OperatorID = "admin"
	}

	if s.responseAuth == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response authority not available")
		return
	}

	session, err := s.responseAuth.UnlockSession(r.Context(), tenantID, req.OperatorID, req.BrowserSessionID, req.BrowserPublicKey, req.TOTPCode)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "unlock failed: "+err.Error())
		return
	}

	s.audit(r, "RESPONSE_SESSION_UNLOCKED", session.SessionID, fmt.Sprintf("Unlocked response session for operator %s tenant %s", req.OperatorID, tenantID))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(session)
}

// handleResponseAuthLock handles locking an active response session.
func (s *Server) handleResponseAuthLock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing session_id")
		return
	}

	if s.responseAuth == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response authority not available")
		return
	}

	if err := s.responseAuth.LockSession(r.Context(), req.SessionID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "lock failed: "+err.Error())
		return
	}

	s.audit(r, "RESPONSE_SESSION_LOCKED", req.SessionID, fmt.Sprintf("Locked response session %s", req.SessionID))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"locked": true})
}

// handleResponseAuthStatus handles querying status of response authority.
func (s *Server) handleResponseAuthStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	if s.responseAuth == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "response authority not available")
		return
	}

	status, err := s.responseAuth.Status(r.Context(), tenantID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to get authority status: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
