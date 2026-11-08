package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"ominull/hub/pkg/grants"
	"ominull/hub/pkg/response"
)

// handleResponseJobs handles listing and creating response jobs.
func (s *Server) handleResponseJobs(w http.ResponseWriter, r *http.Request) {
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	if r.Method == http.MethodGet {
		if s.responseStore == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "response engine not initialized")
			return
		}

		jobID := r.URL.Query().Get("id")
		if jobID != "" {
			job, err := s.responseStore.GetJob(tenantID, jobID)
			if err != nil {
				if errors.Is(err, response.ErrJobNotFound) || errors.Is(err, response.ErrTenantMismatch) {
					writeJSONError(w, http.StatusNotFound, "job not found")
					return
				}
				writeJSONError(w, http.StatusInternalServerError, "failed to get job: "+err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(job)
			return
		}

		endpointID := r.URL.Query().Get("endpoint_id")
		limit := 50
		if qLimit := r.URL.Query().Get("limit"); qLimit != "" {
			if n, err := strconv.Atoi(qLimit); err == nil && n > 0 && n <= 100 {
				limit = n
			}
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
		if r.Header.Get("X-Auth-Method") == "api-key" {
			writeJSONError(w, http.StatusForbidden, "static API keys cannot launch response actions; sign in to the console")
			return
		}
		if r.Header.Get("X-Role") != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin role required")
			return
		}

		var req struct {
			EndpointID     string              `json:"endpoint_id"`
			Kind           response.ActionKind `json:"kind"`
			PayloadJSON    string              `json:"payload_json"`
			IdempotencyKey string              `json:"idempotency_key"`
			ActionDigest   string              `json:"action_digest"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request json: "+err.Error())
			return
		}

		if req.EndpointID == "" || req.Kind == "" || req.PayloadJSON == "" {
			writeJSONError(w, http.StatusBadRequest, "missing endpoint_id, kind, or payload_json")
			return
		}
		// Scripts go through /api/v1/scripts/run, terminals and screens through
		// their own routes, each of which reads what it signs.
		if req.Kind != response.ActionKindForensicCollect {
			writeJSONError(w, http.StatusBadRequest, "this route takes forensic collection only")
			return
		}
		if !s.endpointInScope(w, r, req.EndpointID) {
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

		if s.responseAuth == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "the grant signer is not available")
			return
		}

		grant, err := s.responseAuth.SignGrant(r.Context(), &grants.SignGrantRequest{
			TenantID:     tenantID,
			OperatorID:   operatorID,
			EndpointID:   req.EndpointID,
			ActionKind:   req.Kind,
			ActionDigest: computedDigestHex,
			TTLSeconds:   300,
		})
		if err != nil {
			writeJSONError(w, http.StatusForbidden, "the grant was not signed: "+err.Error())
			return
		}

		job, err := s.responseStore.CreateJob(tenantID, req.EndpointID, req.Kind, operatorID, grant, req.PayloadJSON, req.IdempotencyKey)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to create response job: "+err.Error())
			return
		}

		// If this is a forensic collection, ensure a corresponding evidence bundle exists
		if req.Kind == response.ActionKindForensicCollect && s.evidenceStore != nil {
			var parsedPayload struct {
				BundleID string `json:"bundle_id"`
				Profile  string `json:"profile"`
			}
			_ = json.Unmarshal([]byte(req.PayloadJSON), &parsedPayload)
			bundleID := strings.TrimSpace(parsedPayload.BundleID)
			if bundleID == "" {
				bundleID = job.ID
			}
			profile := strings.TrimSpace(parsedPayload.Profile)
			if profile == "" {
				profile = "diagnostic"
			}
			_, _ = s.evidenceStore.CreateBundleWithID(bundleID, tenantID, req.EndpointID, job.ID, profile, 0)
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

	s.jobWake.notify()
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

	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid ack payload")
		return
	}
	jobID, _ := raw["job_id"].(string)
	leaseID, _ := raw["lease_id"].(string)
	if jobID == "" || leaseID == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid ack payload")
		return
	}

	accepted := true
	if v, ok := raw["accepted"].(bool); ok {
		accepted = v
	}
	rejectionReason, _ := raw["rejection_reason"].(string)
	if rejectionReason != "" {
		accepted = false
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

	if err := s.responseStore.AcknowledgeJob(tenantID, endpointID, jobID, leaseID, accepted, rejectionReason); err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to record ack: "+err.Error())
		return
	}
	s.jobWake.notify()

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

	s.jobWake.notify()
	s.audit(r, "RESPONSE_JOB_COMPLETED", res.JobID, fmt.Sprintf("Completed response job %s state=%s exit_code=%d", res.JobID, res.State, res.ExitCode))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
