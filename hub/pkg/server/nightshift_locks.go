package server

import (
	"net/http"
	"sort"
	"time"

	"ominull/hub/pkg/response"
)

// Lock facts for Nightshift: the relay key may confirm the locks Nightshift's
// installer set (ceiling, host authority, remote access off) without reading
// the fleet. Only machines whose agent reports a lock are listed, and only
// public facts: key ids and roles, never keys.

type nightshiftLockRow struct {
	EndpointID      string                     `json:"endpoint_id"`
	Hostname        string                     `json:"hostname"`
	AgentVersion    string                     `json:"agent_version"`
	Ceiling         string                     `json:"ceiling"`
	Profile         string                     `json:"profile"`
	ManifestSeq     int64                      `json:"manifest_seq"`
	HostFile        bool                       `json:"host_file"` // host_authority.json was there when the agent started
	HostAuthority   bool                       `json:"host_authority"`
	HostKeys        []response.HostKeyReport   `json:"host_keys"`
	HostAllow       []response.HostAllowReport `json:"host_allow"`
	HostError       string                     `json:"host_error,omitempty"`
	RemoteAccessOff bool                       `json:"remote_access_off"`
	ReportedAt      string                     `json:"reported_at"`
	Stale           bool                       `json:"stale"` // report older than the courier accepts
}

// handleNightshiftLocks: GET /api/v1/integrations/nightshift/locks (relay key).
func (s *Server) handleNightshiftLocks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	eps, err := s.store.ListEndpoints("")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.trust.mu.Lock()
	s.trust.init()
	reports := make(map[string]trustReportSeen, len(s.trust.reports))
	for k, v := range s.trust.reports {
		reports[k] = v
	}
	s.trust.mu.Unlock()
	rows := []nightshiftLockRow{}
	for _, ep := range eps {
		seen, ok := reports[ep.ID]
		if ep.Status == "retired" || !ok {
			continue
		}
		rep := seen.report
		hostFile := rep.HostKeys != nil || rep.HostError != "" || rep.HostAuthority
		if rep.Ceiling == "" && !hostFile {
			continue
		}
		row := nightshiftLockRow{
			EndpointID: ep.ID, Hostname: ep.Hostname, AgentVersion: ep.DriverVersion,
			Ceiling: rep.Ceiling, Profile: rep.Profile, ManifestSeq: rep.ManifestSeq,
			HostFile: hostFile, HostAuthority: rep.HostAuthority, HostKeys: rep.HostKeys, HostAllow: rep.HostAllow,
			HostError: rep.HostError, RemoteAccessOff: s.remoteAccessOff(ep.ID),
			ReportedAt: seen.at.UTC().Format(time.RFC3339), Stale: time.Since(seen.at) > signedJobReportAge,
		}
		if row.HostKeys == nil {
			row.HostKeys = []response.HostKeyReport{}
		}
		if row.HostAllow == nil {
			row.HostAllow = []response.HostAllowReport{}
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Hostname+rows[i].EndpointID < rows[j].Hostname+rows[j].EndpointID })
	writeJSON(w, http.StatusOK, map[string]interface{}{"endpoints": rows})
}
