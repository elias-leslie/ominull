package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Retiring an agent release (Nightshift's one-tap undo for a release signed
// in the owner's session): POST /api/v1/agents/rollback halts any staged
// rollout of the version, drops its queued updates, and refuses to roll it
// again. It only stops a release spreading, so it needs no authorization.
// Machines already running it stay on it until a newer release reaches them
// (agents install strictly newer versions only).
const retiredAgentVersionsSetting = "retired_agent_versions"

func (s *Server) retiredAgentVersions() []string {
	raw, _ := s.store.GetSetting(retiredAgentVersionsSetting)
	var list []string
	_ = json.Unmarshal([]byte(raw), &list)
	return list
}

// retiredAgentVersionsList is the retired releases for JSON: never null.
func (s *Server) retiredAgentVersionsList() []string {
	if list := s.retiredAgentVersions(); list != nil {
		return list
	}
	return []string{}
}

func (s *Server) agentVersionRetired(version string) bool {
	for _, v := range s.retiredAgentVersions() {
		if v == version {
			return true
		}
	}
	return false
}

func (s *Server) handleAgentRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Version string `json:"version"`
		Reason  string `json:"reason"`
	}
	if !decodeStrictBody(w, r, &req) {
		return
	}
	req.Version, req.Reason = strings.TrimSpace(req.Version), strings.TrimSpace(req.Reason)
	if !releaseVersion.MatchString(req.Version) || req.Reason == "" || len(req.Reason) > 300 {
		writeJSONError(w, http.StatusBadRequest, "version (X.Y.Z) and a reason (up to 300 characters) are required")
		return
	}
	now := time.Now()
	halted := 0
	if active, err := s.store.AgentRollouts(true, 50); err == nil {
		for _, ro := range active {
			if ro.Version == req.Version {
				s.haltAgentRollout(ro, "retired: "+req.Reason, now)
				halted++
			}
		}
	}
	cancelled, err := s.store.CancelAgentUpdates(req.Version)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	list := s.retiredAgentVersions()
	if !s.agentVersionRetired(req.Version) {
		list = append(list, req.Version)
		sort.Slice(list, func(i, j int) bool { return compareVersions(list[i], list[j]) > 0 })
		if len(list) > 50 {
			list = list[:50]
		}
		raw, _ := json.Marshal(list)
		if err := s.store.SetSetting(retiredAgentVersionsSetting, string(raw)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	var running []string
	if eps, err := s.store.ListEndpoints(""); err == nil {
		for _, ep := range eps {
			if ep.Status != "retired" && ep.DriverVersion == req.Version {
				running = append(running, ep.ID)
			}
		}
	}
	s.audit(r, "AGENT_RELEASE_RETIRED", req.Version, fmt.Sprintf("agent %s retired (%s): %d staged rollout(s) halted, %d queued update(s) dropped, %d machine(s) still run it", req.Version, req.Reason, halted, len(cancelled), len(running)))
	if running == nil {
		running = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"retired": req.Version, "halted": halted, "cancelled": len(cancelled), "running": running,
		"note": "machines already on it stay there until a newer release reaches them",
	})
}
