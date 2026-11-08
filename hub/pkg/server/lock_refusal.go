package server

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

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
// script, from its latest trust report, or "" when its lock and profile allow
// it. The agent's refusal is the real guard, and it refuses silently: without
// this a job waits through 30 offers and then fails with no useful reason.
func lockRefusal(host string, rep *response.AgentTrustReport, capability string) string {
	what := map[string]string{"terminal": "a terminal", "script": "scripts from the hub"}[capability]
	if !ceilingAllows(rep.Ceiling, capability) {
		return fmt.Sprintf("%s is locked to %s on the machine itself; %s is not allowed there", host, rep.Ceiling, what)
	}
	if capability == "script" {
		if rep.HostAuthority {
			return fmt.Sprintf("%s takes only scripts signed by the key pinned on it, and the hub carries none, so run it over SSH", host)
		}
		if rep.Ceiling == "signed-scripts" || rep.Ceiling == "monitor-signed-scripts" {
			return fmt.Sprintf("%s is locked to %s and has no host authority pinned, so it runs no scripts at all", host, rep.Ceiling)
		}
	}
	// Last: the reasons above would still hold after a profile change.
	if caps, ok := response.ProfileCaps(rep.Profile); ok && !slices.Contains(caps, capability) {
		why := fmt.Sprintf("%s is on the %s permission profile, which does not allow %s", host, rep.Profile, what)
		if response.MonitorOnlyProfile(rep.Profile) {
			return why // the hub holds a monitor-only host there, so a raise would not stick
		}
		return why + "; change its profile first"
	}
	return ""
}

// refuseLocked writes a 403 naming every target that would refuse the request,
// before any owner ask, so they don't turn up one attempt at a time.
func (s *Server) refuseLocked(w http.ResponseWriter, capability string, ids ...string) bool {
	var why []string
	for _, id := range ids {
		if one := s.machineRefusal(id, capability); one != "" {
			why = append(why, one)
		}
	}
	if len(why) == 0 {
		return false
	}
	writeJSONError(w, http.StatusForbidden, strings.Join(why, ". "))
	return true
}

// machineRefusal is lockRefusal for one endpoint. A manifest the hub signed
// after the machine's last report counts over that report, so a profile change
// works straight away; a report that came later says what the agent really
// holds, including when it declined that manifest. A machine without a trust
// report is left to its agent.
func (s *Server) machineRefusal(id, capability string) string {
	s.trust.mu.Lock()
	s.trust.init()
	seen, ok := s.trust.reports[id]
	m := s.trust.manifests[id]
	s.trust.mu.Unlock()
	if !ok {
		return ""
	}
	rep := seen.report
	if m != nil && m.Seq > rep.ManifestSeq && seen.at.Before(time.Unix(m.IssuedAt, 0)) {
		rep.Profile = m.Profile
	}
	return lockRefusal(s.endpointLabels([]string{id}), &rep, capability)
}
