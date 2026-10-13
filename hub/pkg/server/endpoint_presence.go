package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"ominull/hub/pkg/storage"
)

// handleEndpointPresence records how often an endpoint is expected to report:
// always on, intermittent (a laptop in use but often shut) or parked (a
// guest that is off unless in use; "lab" is still accepted for parked). Administrator only, and audited,
// because it decides whether a host going dark is reported at all.
func (s *Server) handleEndpointPresence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		EndpointID string `json:"endpoint_id"`
		Presence   string `json:"presence"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.EndpointID = strings.TrimSpace(req.EndpointID)
	req.Presence = storage.NormalizePresence(req.Presence)
	reason := strings.TrimSpace(req.Reason)
	switch {
	case req.EndpointID == "":
		writeJSONError(w, http.StatusBadRequest, "endpoint_id is required")
		return
	case !storage.ValidPresence(req.Presence):
		writeJSONError(w, http.StatusBadRequest, "presence is always_on, intermittent or parked")
		return
	case req.Presence != storage.PresenceAlwaysOn && reason == "":
		writeJSONError(w, http.StatusBadRequest, "say why this host is not always on: a quiet allowance nobody can explain later is one nobody can remove")
		return
	}
	if err := s.store.SetEndpointPresence(req.EndpointID, req.Presence); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrEndpointNotFound) {
			status = http.StatusNotFound
		}
		writeJSONError(w, status, err.Error())
		return
	}
	details := "presence " + req.Presence
	if reason != "" {
		details += ": " + reason
	}
	s.audit(r, "ENDPOINT_PRESENCE_SET", req.EndpointID, details)
	writeJSON(w, http.StatusOK, map[string]string{"endpoint_id": req.EndpointID, "presence": req.Presence})
}
