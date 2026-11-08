package server

import (
	"encoding/json"
	"net/http"
	"time"
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

// handleTopologyWorkspace keeps machine identity, addresses and observed communication
// apart: traffic-only addresses stay separate nodes and a matching name never merges
// hosts. Arrows keep the recorded source and destination and do not prove which side
// started a session. Counts are observations, which can include several reporters, not
// sessions.
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
