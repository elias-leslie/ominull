package server

import (
	"fmt"
	"net/http"

	"ominull/hub/pkg/response"
)

// ceilingAllows mirrors the agent's Trust_CeilingHas (agent/include/agent_trust.h;
// levels in docs/HOST_AUTHORITY.md): what a lock level set on the machine
// leaves of the terminal and scripts. Remote screen has its own preflight
// (screenTrustRefusal).
func ceilingAllows(ceiling, capability string) bool {
	switch ceiling {
	case "", "engagement":
		return true
	case "respond":
		return capability != "script"
	case "signed-scripts", "monitor-signed-scripts":
		return capability == "script"
	}
	return false // monitor, isolate, or a level this hub does not know
}

// lockRefusal says why the machine would refuse a hub-signed terminal or
// script, from its latest trust report, or "" when its lock allows it. The
// agent's refusal is the real guard; this only spares the owner a tap on a
// request that cannot run.
func lockRefusal(host string, rep *response.AgentTrustReport, capability string) string {
	what := map[string]string{"terminal": "a terminal", "script": "scripts from the hub"}[capability]
	if !ceilingAllows(rep.Ceiling, capability) {
		return fmt.Sprintf("%s is locked to %s on the machine itself; %s is not allowed there", host, rep.Ceiling, what)
	}
	if capability != "script" {
		return ""
	}
	if rep.HostAuthority {
		return fmt.Sprintf("%s takes only Nightshift-signed scripts (a host authority is pinned there); run released packages with ominullctl host-script run", host)
	}
	if rep.Ceiling == "signed-scripts" || rep.Ceiling == "monitor-signed-scripts" {
		return fmt.Sprintf("%s is locked to %s and has no host authority pinned, so it runs no scripts at all", host, rep.Ceiling)
	}
	return ""
}

// refuseLocked writes a 403 with the plain reason, before any owner ask, when
// one of the targets is locked against the request. A machine without a
// trust report is left to its agent.
func (s *Server) refuseLocked(w http.ResponseWriter, capability string, ids ...string) bool {
	for _, id := range ids {
		s.trust.mu.Lock()
		s.trust.init()
		seen, ok := s.trust.reports[id]
		s.trust.mu.Unlock()
		if !ok {
			continue
		}
		if why := lockRefusal(s.endpointLabels([]string{id}), &seen.report, capability); why != "" {
			writeJSONError(w, http.StatusForbidden, why)
			return true
		}
	}
	return false
}
