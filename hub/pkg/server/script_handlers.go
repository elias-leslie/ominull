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
	"time"

	"ominull/hub/pkg/response"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/scripts"
)

// handleScripts handles script library listing and management.
func (s *Server) handleScripts(w http.ResponseWriter, r *http.Request) {
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	if s.scriptsStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "scripts store not initialized")
		return
	}

	if r.Method == http.MethodGet {
		id := r.URL.Query().Get("id")
		verStr := r.URL.Query().Get("version")
		if id != "" && verStr != "" {
			ver, err := strconv.Atoi(verStr)
			if err != nil || ver <= 0 {
				writeJSONError(w, http.StatusBadRequest, "invalid version parameter")
				return
			}
			sv, err := s.scriptsStore.GetScriptVersion(tenantID, id, ver)
			if err != nil {
				if errors.Is(err, scripts.ErrNotFound) || errors.Is(err, scripts.ErrTenantMismatch) {
					writeJSONError(w, http.StatusNotFound, "script version not found")
					return
				}
				writeJSONError(w, http.StatusInternalServerError, "failed to get script version: "+err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sv)
			return
		}
		if id != "" {
			sc, err := s.scriptsStore.GetScript(tenantID, id)
			if err != nil {
				if errors.Is(err, scripts.ErrNotFound) || errors.Is(err, scripts.ErrTenantMismatch) {
					writeJSONError(w, http.StatusNotFound, "script not found")
					return
				}
				writeJSONError(w, http.StatusInternalServerError, "failed to get script: "+err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sc)
			return
		}

		list, err := s.scriptsStore.ListScripts(tenantID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to list scripts: "+err.Error())
			return
		}
		if list == nil {
			list = []*scripts.Script{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"scripts": list,
		})
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			ID                  string `json:"id,omitempty"`
			Name                string `json:"name"`
			Description         string `json:"description"`
			Interpreter         string `json:"interpreter"`
			Source              string `json:"source"`
			ParameterSchemaJSON string `json:"parameter_schema_json"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}

		operatorID := s.operatorFromRequest(r)
		if operatorID == "" {
			operatorID = "operator"
		}

		if req.ID != "" {
			// Append new version under tenant control
			sv, err := s.scriptsStore.UpdateScript(tenantID, req.ID, req.Source, req.ParameterSchemaJSON, operatorID)
			if err != nil {
				if errors.Is(err, scripts.ErrNotFound) || errors.Is(err, scripts.ErrTenantMismatch) {
					writeJSONError(w, http.StatusNotFound, "script not found")
					return
				}
				if errors.Is(err, scripts.ErrScriptRetired) {
					writeJSONError(w, http.StatusBadRequest, "cannot update retired script")
					return
				}
				if errors.Is(err, scripts.ErrScriptTooLarge) {
					writeJSONError(w, http.StatusBadRequest, "script source exceeds size limit (64 KiB)")
					return
				}
				writeJSONError(w, http.StatusBadRequest, "failed to update script: "+err.Error())
				return
			}
			s.audit(r, "SCRIPT_VERSION_APPENDED", req.ID, fmt.Sprintf("Appended script version %d (digest: %s)", sv.Version, sv.DigestSHA256))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sv)
			return
		}

		// Create new script definition and version 1
		sc, sv, err := s.scriptsStore.CreateScript(tenantID, req.Name, req.Description, req.Interpreter, req.Source, req.ParameterSchemaJSON, operatorID)
		if err != nil {
			if errors.Is(err, scripts.ErrInvalidInterpreter) {
				writeJSONError(w, http.StatusBadRequest, "unsupported interpreter; must be /bin/sh, /bin/bash, powershell.exe, cmd.exe, or pwsh.exe")
				return
			}
			if errors.Is(err, scripts.ErrScriptTooLarge) {
				writeJSONError(w, http.StatusBadRequest, "script source exceeds size limit (64 KiB)")
				return
			}
			writeJSONError(w, http.StatusBadRequest, "failed to create script: "+err.Error())
			return
		}
		s.audit(r, "SCRIPT_CREATED", sc.ID, fmt.Sprintf("Created script %s (digest: %s)", sc.Name, sv.DigestSHA256))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"script":  sc,
			"version": sv,
		})
		return
	}

	if r.Method == http.MethodDelete {
		id := r.URL.Query().Get("id")
		if id == "" {
			writeJSONError(w, http.StatusBadRequest, "missing script id parameter")
			return
		}
		err := s.scriptsStore.RetireScript(tenantID, id)
		if err != nil {
			if errors.Is(err, scripts.ErrNotFound) || errors.Is(err, scripts.ErrTenantMismatch) {
				writeJSONError(w, http.StatusNotFound, "script not found")
				return
			}
			writeJSONError(w, http.StatusInternalServerError, "failed to retire script: "+err.Error())
			return
		}
		s.audit(r, "SCRIPT_RETIRED", id, fmt.Sprintf("Retired script %s", id))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"retired": true,
			"id":      id,
		})
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// handleScriptsRun handles executing a versioned script with a signed grant.
func (s *Server) handleScriptsRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Fail-closed check: static API keys cannot execute scripts; active console session required
	if r.Header.Get("X-Auth-Method") == "api-key" {
		writeJSONError(w, http.StatusForbidden, "static API keys cannot execute scripts; an active console response session is required")
		return
	}

	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	if s.scriptsStore == nil || s.responseStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "scripts or response engine not initialized")
		return
	}

	var req struct {
		ScriptID       string                    `json:"script_id"`
		Version        int                       `json:"version"`
		EndpointID     string                    `json:"endpoint_id"`
		Parameters     map[string]string         `json:"parameters"`
		TimeoutSeconds int                       `json:"timeout_seconds"`
		MaxOutputBytes int64                     `json:"max_output_bytes"`
		SessionID      string                    `json:"session_id"`
		ActionDigest   string                    `json:"action_digest"`
		Proof          *responseauth.ActionProof `json:"proof"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}

	if req.ScriptID == "" || req.Version <= 0 || req.EndpointID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing script_id, version, or endpoint_id")
		return
	}

	// Retrieve script and verify tenant ownership & non-retired status
	sc, err := s.scriptsStore.GetScript(tenantID, req.ScriptID)
	if err != nil {
		if errors.Is(err, scripts.ErrNotFound) || errors.Is(err, scripts.ErrTenantMismatch) {
			writeJSONError(w, http.StatusNotFound, "script not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to query script: "+err.Error())
		return
	}
	if sc.Retired {
		writeJSONError(w, http.StatusBadRequest, "cannot execute retired script")
		return
	}

	sv, err := s.scriptsStore.GetScriptVersion(tenantID, req.ScriptID, req.Version)
	if err != nil {
		if errors.Is(err, scripts.ErrNotFound) || errors.Is(err, scripts.ErrTenantMismatch) {
			writeJSONError(w, http.StatusNotFound, "script version not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to query script version: "+err.Error())
		return
	}

	// Validate typed parameter schema
	paramSchema, err := scripts.ValidateSchema(sv.ParameterSchemaJSON)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "invalid script parameter schema: "+err.Error())
		return
	}
	if err := scripts.ValidateParameters(paramSchema, req.Parameters); err != nil {
		writeJSONError(w, http.StatusBadRequest, "parameter validation failed: "+err.Error())
		return
	}

	// Verify target endpoint exists and matches tenant
	ep, err := s.store.GetEndpoint(req.EndpointID)
	if err != nil || ep == nil {
		writeJSONError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	if ep.TenantID != tenantID && tenantID != "default" {
		writeJSONError(w, http.StatusForbidden, "endpoint tenant mismatch")
		return
	}

	operatorID := s.operatorFromRequest(r)
	if operatorID == "" {
		operatorID = "operator"
	}

	// Bound execution parameters
	timeout := req.TimeoutSeconds
	if timeout <= 0 || timeout > 300 {
		timeout = 60
	}
	maxOutput := req.MaxOutputBytes
	if maxOutput <= 0 || maxOutput > 5242880 {
		maxOutput = 1048576
	}

	payload := response.ScriptExecPayload{
		ScriptID:       req.ScriptID,
		ScriptVersion:  req.Version,
		ScriptDigest:   sv.DigestSHA256,
		Interpreter:    sc.Interpreter,
		Source:         sv.Source,
		Parameters:     req.Parameters,
		TimeoutSeconds: timeout,
		MaxOutputBytes: maxOutput,
	}
	payloadJSONBytes, err := json.Marshal(payload)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to marshal script payload: "+err.Error())
		return
	}

	// Server-side independent SHA-256 digest recomputation
	hasher := sha256.New()
	hasher.Write(payloadJSONBytes)
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

	// Validate action proof and sign grant
	grant, err := s.responseAuth.SignGrant(r.Context(), &responseauth.SignGrantRequest{
		TenantID:      tenantID,
		OperatorID:    operatorID,
		SessionID:     req.SessionID,
		EndpointID:    req.EndpointID,
		ActionKind:    response.ActionKindScriptExec,
		ActionDigest:  computedDigestHex,
		ActionPayload: json.RawMessage(payloadJSONBytes),
		TTLSeconds:    300,
		Proof:         req.Proof,
	})
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "response authority denied script execution: "+err.Error())
		return
	}

	job, err := s.responseStore.CreateJob(tenantID, req.EndpointID, response.ActionKindScriptExec, operatorID, grant, string(payloadJSONBytes), "")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to create script execution job: "+err.Error())
		return
	}

	s.audit(r, "SCRIPT_RUN_DISPATCHED", job.ID, fmt.Sprintf("Dispatched script %s v%d (%s) to %s", sc.Name, req.Version, sc.Interpreter, req.EndpointID))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(job)
}

// handleScriptsDigest computes the canonical action digest for script execution with the given parameters and bounds.
func (s *Server) handleScriptsDigest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	if s.scriptsStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "scripts store not initialized")
		return
	}

	var req struct {
		ScriptID       string            `json:"script_id"`
		Version        int               `json:"version"`
		Parameters     map[string]string `json:"parameters"`
		TimeoutSeconds int               `json:"timeout_seconds"`
		MaxOutputBytes int64             `json:"max_output_bytes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}

	if req.ScriptID == "" || req.Version <= 0 {
		writeJSONError(w, http.StatusBadRequest, "missing script_id or version")
		return
	}

	sc, err := s.scriptsStore.GetScript(tenantID, req.ScriptID)
	if err != nil {
		if errors.Is(err, scripts.ErrNotFound) || errors.Is(err, scripts.ErrTenantMismatch) {
			writeJSONError(w, http.StatusNotFound, "script not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to get script: "+err.Error())
		return
	}
	if sc.Retired {
		writeJSONError(w, http.StatusBadRequest, "cannot execute retired script")
		return
	}

	sv, err := s.scriptsStore.GetScriptVersion(tenantID, req.ScriptID, req.Version)
	if err != nil {
		if errors.Is(err, scripts.ErrNotFound) || errors.Is(err, scripts.ErrTenantMismatch) {
			writeJSONError(w, http.StatusNotFound, "script version not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to get script version: "+err.Error())
		return
	}

	if sv.ParameterSchemaJSON != "" {
		paramSchema, err := scripts.ValidateSchema(sv.ParameterSchemaJSON)
		if err == nil {
			if err := scripts.ValidateParameters(paramSchema, req.Parameters); err != nil {
				writeJSONError(w, http.StatusBadRequest, "parameter validation failed: "+err.Error())
				return
			}
		}
	}

	timeout := req.TimeoutSeconds
	if timeout <= 0 || timeout > 300 {
		timeout = 60
	}
	maxOutput := req.MaxOutputBytes
	if maxOutput <= 0 || maxOutput > 5242880 {
		maxOutput = 1048576
	}

	payload := response.ScriptExecPayload{
		ScriptID:       req.ScriptID,
		ScriptVersion:  req.Version,
		ScriptDigest:   sv.DigestSHA256,
		Interpreter:    sc.Interpreter,
		Source:         sv.Source,
		Parameters:     req.Parameters,
		TimeoutSeconds: timeout,
		MaxOutputBytes: maxOutput,
	}

	digestHex, err := response.ComputeActionDigest(payload)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to compute action digest: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"action_digest": digestHex,
		"script_digest": sv.DigestSHA256,
	})
}

// handleScriptSchedules manages frozen script execution schedules.
func (s *Server) handleScriptSchedules(w http.ResponseWriter, r *http.Request) {
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}

	if s.scriptsStore == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "scripts store not initialized")
		return
	}

	if r.Method == http.MethodGet {
		id := r.URL.Query().Get("id")
		if id != "" {
			sched, err := s.scriptsStore.GetSchedule(tenantID, id)
			if err != nil {
				if errors.Is(err, scripts.ErrScheduleNotFound) {
					writeJSONError(w, http.StatusNotFound, "schedule not found")
					return
				}
				writeJSONError(w, http.StatusInternalServerError, "failed to query schedule: "+err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sched)
			return
		}

		schedules, err := s.scriptsStore.ListSchedules(tenantID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to list schedules: "+err.Error())
			return
		}
		if schedules == nil {
			schedules = []*scripts.ScriptSchedule{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"schedules": schedules,
			"count":     len(schedules),
		})
		return
	}

	if r.Method == http.MethodPost {
		// Fail-closed gate: static API keys cannot create schedules
		if r.Header.Get("X-Auth-Method") == "api-key" {
			writeJSONError(w, http.StatusForbidden, "static API keys cannot schedule scripts; an active console response session is required")
			return
		}

		var req struct {
			ScriptID        string                    `json:"script_id"`
			Version         int                       `json:"version"`
			TargetEndpoints []string                  `json:"target_endpoints"`
			Parameters      map[string]string         `json:"parameters"`
			Recurrence      string                    `json:"recurrence"`
			StartTime       time.Time                 `json:"start_time"`
			EndTime         *time.Time                `json:"end_time,omitempty"`
			MaxRuns         int                       `json:"max_runs"`
			TimeoutSeconds  int                       `json:"timeout_seconds"`
			MaxOutputBytes  int64                     `json:"max_output_bytes"`
			SessionID       string                    `json:"session_id"`
			ActionDigest    string                    `json:"action_digest"`
			Proof           *responseauth.ActionProof `json:"proof"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}

		if req.ScriptID == "" || req.Version <= 0 || len(req.TargetEndpoints) == 0 {
			writeJSONError(w, http.StatusBadRequest, "missing script_id, version, or target_endpoints")
			return
		}

		operatorID := s.operatorFromRequest(r)
		if operatorID == "" {
			operatorID = "operator"
		}

		// Verify active response session if response authority configured
		if s.responseAuth != nil && req.SessionID != "" {
			st, err := s.responseAuth.Status(r.Context(), tenantID)
			if err != nil || st.ActiveSessions <= 0 {
				writeJSONError(w, http.StatusForbidden, "active response authority session required to create schedules")
				return
			}
		}

		sched, err := s.scriptsStore.CreateSchedule(
			tenantID, req.ScriptID, req.Version,
			req.TargetEndpoints, req.Parameters, req.Recurrence,
			req.StartTime, req.EndTime, req.MaxRuns,
			req.TimeoutSeconds, req.MaxOutputBytes, operatorID,
		)
		if err != nil {
			if errors.Is(err, scripts.ErrNotFound) {
				writeJSONError(w, http.StatusNotFound, "script or version not found")
				return
			}
			if errors.Is(err, scripts.ErrScriptRetired) {
				writeJSONError(w, http.StatusBadRequest, "cannot schedule retired script")
				return
			}
			if errors.Is(err, scripts.ErrEmptyTargetEndpoints) {
				writeJSONError(w, http.StatusBadRequest, "schedule requires explicit target endpoints")
				return
			}
			writeJSONError(w, http.StatusBadRequest, "failed to create schedule: "+err.Error())
			return
		}

		s.audit(r, "SCRIPT_SCHEDULE_CREATED", sched.ID, fmt.Sprintf("Created frozen schedule for script %s v%d (digest: %s, targets: %v)", sched.ScriptID, sched.Version, sched.ScriptDigest, sched.TargetEndpoints))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(sched)
		return
	}

	if r.Method == http.MethodDelete {
		id := r.URL.Query().Get("id")
		if id == "" {
			writeJSONError(w, http.StatusBadRequest, "missing schedule id parameter")
			return
		}

		if err := s.scriptsStore.CancelSchedule(tenantID, id); err != nil {
			if errors.Is(err, scripts.ErrScheduleNotFound) {
				writeJSONError(w, http.StatusNotFound, "schedule not found or already cancelled")
				return
			}
			writeJSONError(w, http.StatusInternalServerError, "failed to cancel schedule: "+err.Error())
			return
		}

		s.audit(r, "SCRIPT_SCHEDULE_CANCELLED", id, fmt.Sprintf("Cancelled schedule %s", id))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"cancelled": true,
			"id":        id,
		})
		return
	}

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}
