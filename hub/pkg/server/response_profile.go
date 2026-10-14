package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

// Monitor-only endpoints (storage/response_profile.go): a hypervisor is never
// isolated at host level, because host isolation leaves FORWARD open; its
// guests are contained one by one on the hypervisor's per-guest firewall.
// Making an endpoint monitor-only only narrows what the hub may do, so an
// administrator can set it directly (never while it is isolated: that would
// release the isolation without the owner). Lifting it is a capability raise
// and takes an owner approval for the exact revision the owner was shown.

// guestContainmentHint tells an operator where guest containment lives. The
// executor that runs it holds the hypervisor's management access; the hub
// does not.
const guestContainmentHint = "contain its guests one by one on the hypervisor's per-guest firewall (Nightshift: nightshift contain-guest VMID)"

// refuseMonitorOnly answers 409 and returns true when the endpoint is
// monitor-only. Unknown endpoints are left to the caller.
func (s *Server) refuseMonitorOnly(w http.ResponseWriter, endpointID string) bool {
	ep, err := s.store.GetEndpoint(endpointID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return true
	}
	if ep == nil || !ep.MonitorOnly {
		return false
	}
	writeMonitorOnly(w, []string{ep.ID}, ep.MonitorOnlyReason())
	return true
}

func writeMonitorOnly(w http.ResponseWriter, ids []string, reason string) {
	msg := "host isolation refused: " + strings.Join(ids, ", ") + " is monitor-only"
	if reason != "" {
		msg += " (" + reason + ")"
	}
	writeJSON(w, http.StatusConflict, map[string]interface{}{
		"error":         msg + ". Isolating a hypervisor cuts its management while its guests keep talking; " + guestContainmentHint,
		"monitor_only":  ids,
		"contain_guest": guestContainmentHint,
	})
}

// splitMonitorOnly drops monitor-only endpoints from an isolation target set.
func (s *Server) splitMonitorOnly(w http.ResponseWriter, ids []string) (allowed, monitor []string, ok bool) {
	allowed, monitor, err := s.store.SplitMonitorOnly(ids)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return nil, nil, false
	}
	return allowed, monitor, true
}

type responseProfileRequest struct {
	EndpointID string `json:"endpoint_id"`
	Reason     string `json:"reason"`
	Revision   *int64 `json:"revision,omitempty"` // allow-isolation: the setting's revision being lifted
}

func decodeResponseProfile(w http.ResponseWriter, body []byte) (responseProfileRequest, bool) {
	var req responseProfileRequest
	if !decodeInto(w, body, &req) {
		return req, false
	}
	req.EndpointID = strings.TrimSpace(req.EndpointID)
	req.Reason = strings.TrimSpace(req.Reason)
	switch {
	case req.EndpointID == "":
		writeJSONError(w, http.StatusBadRequest, "endpoint_id is required")
		return req, false
	case req.Reason == "" || len(req.Reason) > 300:
		writeJSONError(w, http.StatusBadRequest, "reason is required (at most 300 characters)")
		return req, false
	}
	return req, true
}

// handleMonitorOnly makes an endpoint monitor-only (admin; narrowing only).
// It also clears a recorded isolation: the agent is no longer told to keep one.
func (s *Server) handleMonitorOnly(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req, ok := decodeResponseProfile(w, body)
	if !ok || !s.endpointInScope(w, r, req.EndpointID) {
		return
	}
	rev, err := s.store.SetEndpointMonitorOnly(req.EndpointID)
	if err != nil {
		writeProfileError(w, err)
		return
	}
	s.audit(r, "ENDPOINT_MONITOR_ONLY_SET", req.EndpointID, "Host isolation refused from now on: "+req.Reason)
	writeJSON(w, http.StatusOK, map[string]interface{}{"endpoint_id": req.EndpointID, "response_profile": storage.ResponseProfileMonitor,
		"monitor_only": true, "response_profile_rev": rev})
}

func writeProfileError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, storage.ErrEndpointNotFound):
		writeJSONError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, storage.ErrIsolated), errors.Is(err, storage.ErrProfileChanged):
		writeJSONError(w, http.StatusConflict, err.Error())
	default:
		writeJSONError(w, http.StatusInternalServerError, err.Error())
	}
}

// resolveAllowIsolation describes lifting the operator's monitor-only setting
// for the owner's approval. The body names the setting's current revision, and
// the approval covers that body, so it cannot lift a later setting.
func (s *Server) resolveAllowIsolation(w http.ResponseWriter, r *http.Request, body []byte) (*approvalPlan, bool) {
	if r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "admin role required")
		return nil, false
	}
	req, ok := decodeResponseProfile(w, body)
	if !ok || !s.endpointInScope(w, r, req.EndpointID) {
		return nil, false
	}
	ep, err := s.store.GetEndpoint(req.EndpointID)
	switch {
	case err != nil:
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return nil, false
	case ep == nil:
		writeJSONError(w, http.StatusNotFound, "endpoint not found")
		return nil, false
	case !ep.MonitorOnly:
		writeJSONError(w, http.StatusConflict, "endpoint is not monitor-only")
		return nil, false
	case req.Revision == nil || *req.Revision != ep.ResponseProfileRev:
		writeJSON(w, http.StatusConflict, map[string]interface{}{
			"error": "name the setting's current revision", "response_profile_rev": ep.ResponseProfileRev})
		return nil, false
	}
	return &approvalPlan{Kind: responseauth.ActionKindIsolation, Action: "Allow host isolation",
		Summary: "Let " + s.endpointLabels([]string{req.EndpointID}) + " be isolated at host level again", Targets: []string{req.EndpointID}}, true
}

// handleAllowIsolation clears the operator's monitor-only setting (owner
// approved), only at the revision the approval names.
func (s *Server) handleAllowIsolation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req responseProfileRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.EndpointID = strings.TrimSpace(req.EndpointID)
	if ids := grantedTargets(r); ids != nil && (len(ids) != 1 || ids[0] != req.EndpointID) {
		writeJSONError(w, http.StatusForbidden, "the approval covers a different endpoint")
		return
	}
	if req.Revision == nil {
		writeJSONError(w, http.StatusBadRequest, "revision is required")
		return
	}
	if !s.endpointInScope(w, r, req.EndpointID) {
		return
	}
	rev, err := s.store.LiftMonitorOnly(req.EndpointID, *req.Revision)
	if err != nil {
		writeProfileError(w, err)
		return
	}
	s.audit(r, "ENDPOINT_MONITOR_ONLY_LIFTED", req.EndpointID, fmt.Sprintf("Operator monitor-only setting (revision %d) lifted: %s",
		*req.Revision, strings.TrimSpace(req.Reason)))
	writeJSON(w, http.StatusOK, map[string]interface{}{"endpoint_id": req.EndpointID, "response_profile": "", "monitor_only": false,
		"response_profile_rev": rev})
}
