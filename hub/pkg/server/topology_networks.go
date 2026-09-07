package server

import (
	"encoding/json"
	"github.com/google/uuid"
	"net/http"
	"ominull/hub/pkg/storage"
	"time"
)

func (s *Server) handleTopologyNetworks(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
	case http.MethodPut:
		var networks []storage.TopologyNetwork
		if err := json.NewDecoder(r.Body).Decode(&networks); err != nil {
			http.Error(w, "invalid network list", http.StatusBadRequest)
			return
		}
		if err := storage.ValidateTopologyNetworks(networks); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.store.SetTopologyNetworks(networks); err != nil {
			http.Error(w, "could not save estate networks", http.StatusInternalServerError)
			return
		}
		s.topology.mu.Lock()
		s.topology.entries = nil
		s.topology.mu.Unlock()
		_ = s.store.RecordAudit(storage.AuditEntry{ID: uuid.NewString(), UserID: r.Header.Get("X-User-ID"), Username: r.Header.Get("X-Username"), Action: "CONFIGURE_ESTATE_NETWORKS", Resource: "topology.networks", IPAddress: clientIP(r), Timestamp: time.Now().UTC()})
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	networks, err := s.store.TopologyNetworks()
	if err != nil {
		http.Error(w, "could not read estate networks", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(networks)
}
