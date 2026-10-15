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
// guest that is off unless in use; "lab" is still accepted for parked).
// Administrator only. It decides whether a host going dark is reported at all,
// so it goes through the detection-policy choke point: watching a host less
// closely waits for the owner's tap; watching it more closely applies at once
// with a note.
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
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	ep, err := s.store.GetEndpoint(req.EndpointID)
	if err != nil || ep == nil {
		status, msg := http.StatusNotFound, storage.ErrEndpointNotFound.Error()
		if err != nil {
			status, msg = http.StatusInternalServerError, err.Error()
		}
		writeJSONError(w, status, msg)
		return
	}
	before := watchView(*ep)
	after := before
	after.Presence = req.Presence
	after.Reason = reason
	change := policyChange{policy: "endpoint_watch", op: "presence", target: "endpoint:" + ep.ID,
		before: before, after: after,
		wording: "presence of " + ep.ID + " " + before.Presence + " -> " + req.Presence}
	if presenceRank(req.Presence) > presenceRank(before.Presence) {
		change.loosens = []string{"presence"}
	}
	approvalID, ok := s.policyApproved(w, r, change)
	if !ok {
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
	if before.Presence != req.Presence {
		if reason != "" {
			change.wording += ": " + reason
		}
		s.notePolicyChange(r, change, approvalID)
	}
	writeJSON(w, http.StatusOK, map[string]string{"endpoint_id": req.EndpointID, "presence": req.Presence})
}

// endpointWatch is a host as the silence floor watches it, for the owner's
// approval: the digest binds it, so an approval asked while the host was
// watched one way is refused once that has changed.
type endpointWatch struct {
	EndpointID string `json:"endpoint_id"`
	Hostname   string `json:"hostname"`
	Presence   string `json:"presence"`
	Status     string `json:"status"`
	Isolated   bool   `json:"isolated"`
	Reason     string `json:"reason,omitempty"`
}

func watchView(ep storage.Endpoint) endpointWatch {
	presence := storage.NormalizePresence(ep.Presence)
	if presence == "" {
		presence = storage.PresenceAlwaysOn
	}
	status := ep.Status
	if status != "retired" {
		// online and offline only describe the last heartbeat; the
		// approval binds whether the host is watched, not when it last spoke.
		status = "active"
	}
	return endpointWatch{EndpointID: ep.ID, Hostname: ep.Hostname, Presence: presence, Status: status, Isolated: ep.IsIsolated}
}

// presenceRank orders presence from most to least closely watched.
func presenceRank(p string) int {
	switch p {
	case storage.PresenceIntermittent:
		return 1
	case storage.PresenceParked:
		return 2
	}
	return 0
}
