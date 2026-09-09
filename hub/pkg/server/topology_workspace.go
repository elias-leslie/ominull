package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"ominull/hub/pkg/storage"
)

func requireTopologyOperator(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Role") {
		case "admin", "analyst", "auditor":
			next(w, r)
		default:
			writeJSONError(w, http.StatusForbidden, "operator identity required")
		}
	}
}
func topologyWindow(raw string) time.Duration {
	switch raw {
	case "1h":
		return time.Hour
	case "6h":
		return 6 * time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}
func (s *Server) handleTopologyWorkspace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, 405, "method not allowed")
		return
	}
	window := topologyWindow(r.URL.Query().Get("window"))
	key := "workspace:" + window.String()
	entry, err := s.topology.snapshot(key, func() ([]byte, error) {
		graph, err := s.store.GetTopologyWorkspace(window)
		if err != nil {
			return nil, err
		}
		return json.Marshal(graph)
	})
	if err != nil {
		writeJSONError(w, 500, "could not read topology")
		return
	}
	writeSnapshot(w, r, entry)
}
func (s *Server) handleTopologyViews(w http.ResponseWriter, r *http.Request) {
	// Identity is populated only by authMiddleware. Never accept an owner in a body.
	owner := r.Header.Get("X-User-ID")
	if owner == "" {
		owner = r.Header.Get("X-Username")
	}
	if owner == "" {
		writeJSONError(w, 403, "operator identity required")
		return
	}
	if r.Method == http.MethodGet {
		views, err := s.store.ListTopologyViews(owner)
		if err != nil {
			writeJSONError(w, 500, "could not read saved views")
			return
		}
		writeJSON(w, 200, map[string]interface{}{"views": views})
		return
	}
	if r.Header.Get("X-Role") == "auditor" {
		writeJSONError(w, 403, "auditors cannot save views")
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		writeJSONError(w, 405, "method not allowed")
		return
	}
	var v storage.TopologyView
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1100000))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		writeJSONError(w, 400, "invalid saved view")
		return
	}
	if dec.Decode(new(interface{})) != io.EOF {
		writeJSONError(w, 400, "invalid saved view")
		return
	}
	var err error
	if r.Method == http.MethodDelete {
		err = s.store.DeleteTopologyView(owner, v.ID, v.Revision)
	} else {
		v, err = s.store.SaveTopologyView(owner, v)
	}
	if errors.Is(err, storage.ErrTopologyViewConflict) {
		writeJSONError(w, 409, err.Error())
		return
	}
	if err != nil {
		writeJSONError(w, 400, "could not save view; check name and size")
		return
	}
	writeJSON(w, 200, v)
}
