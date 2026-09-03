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
			ver, _ := strconv.Atoi(verStr)
			sv, err := s.scriptsStore.GetScriptVersion(id, ver)
			if err != nil {
				writeJSONError(w, http.StatusNotFound, "script version not found")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sv)
			return
		}
		if id != "" {
			sc, err := s.scriptsStore.GetScript(id)
			if err != nil {
				writeJSONError(w, http.StatusNotFound, "script not found")
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

		if req.ID != "" {
			// Update version
			sv, err := s.scriptsStore.UpdateScript(req.ID, req.Source, req.ParameterSchemaJSON, operatorID)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "failed to update script: "+err.Error())
				return
			}
			s.audit(r, "SCRIPT_VERSION_APPENDED", req.ID, fmt.Sprintf("Appended script version %d (digest: %s)", sv.Version, sv.DigestSHA256))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sv)
			return
		}

		// Create new
		sc, sv, err := s.scriptsStore.CreateScript(tenantID, req.Name, req.Description, req.Interpreter, req.Source, req.ParameterSchemaJSON, operatorID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to create script: "+err.Error())
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

	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// handleScriptsRun handles executing a versioned script with a signed grant.
func (s *Server) handleScriptsRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
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
		ScriptID     string                    `json:"script_id"`
		Version      int                       `json:"version"`
		EndpointID   string                    `json:"endpoint_id"`
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

	sv, err := s.scriptsStore.GetScriptVersion(req.ScriptID, req.Version)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "script version not found")
		return
	}

	operatorID := s.operatorFromRequest(r)

	payload := response.ScriptExecPayload{
		ScriptID:       req.ScriptID,
		ScriptVersion:  req.Version,
		ScriptDigest:   sv.DigestSHA256,
		Source:         sv.Source,
		Parameters:     req.Parameters,
		TimeoutSeconds: req.TimeoutSeconds,
		MaxOutputBytes: req.MaxOutputBytes,
	}
	payloadJSONBytes, err := json.Marshal(payload)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to marshal script payload: "+err.Error())
		return
	}

	// Server-side independent digest recomputation
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

	s.audit(r, "SCRIPT_RUN_DISPATCHED", job.ID, fmt.Sprintf("Dispatched script %s v%d to %s", req.ScriptID, req.Version, req.EndpointID))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(job)
}
