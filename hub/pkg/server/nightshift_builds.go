package server

import (
	"net/http"
	"sort"
	"time"
)

// Agent builds for Nightshift: which build each enrolled agent runs, so
// Nightshift can check that none still trusts a retired release key (the key
// rotation of 1.8.71 is the first; which builds count as past it is
// Nightshift's setting, not the hub's). Relay key; retired endpoints are
// left out, offline ones stay (an old build that is off still trusts the old
// key when it wakes).

type nightshiftBuildRow struct {
	EndpointID   string `json:"endpoint_id"`
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version"`
	Presence     string `json:"presence"`
	LastSeen     string `json:"last_seen"`
}

// handleNightshiftBuilds: GET /api/v1/integrations/nightshift/agent-builds (relay key).
func (s *Server) handleNightshiftBuilds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	eps, err := s.store.ListEndpoints("")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows := []nightshiftBuildRow{}
	for _, ep := range eps {
		if ep.Status == "retired" {
			continue
		}
		row := nightshiftBuildRow{EndpointID: ep.ID, Hostname: ep.Hostname, AgentVersion: ep.DriverVersion, Presence: ep.Presence}
		if !ep.LastSeenAt.IsZero() {
			row.LastSeen = ep.LastSeenAt.UTC().Format(time.RFC3339)
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Hostname+rows[i].EndpointID < rows[j].Hostname+rows[j].EndpointID })
	writeJSON(w, http.StatusOK, map[string]interface{}{"endpoints": rows})
}
