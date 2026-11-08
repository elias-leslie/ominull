package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// maxAgentSessionsPosted bounds one report from the workstation.
const maxAgentSessionsPosted = 500

// handleAgentSessions is the names behind the window ids flows carry. The
// endpoint agent can only see a window's id; the workstation that runs the
// windows posts their names (scripts/sync-agent-sessions.py). GET lists them.
func (s *Server) handleAgentSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// What the owner's agent windows are called is for operators, not the tenant key.
		if r.Header.Get("X-Role") == "tenant" {
			writeJSONError(w, http.StatusForbidden, "operator role required")
			return
		}
		list, err := s.store.ListAgentSessions()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
	case http.MethodPost:
		requireAdmin(s.postAgentSessions)(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) postAgentSessions(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Sessions []storage.AgentSession `json:"sessions"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Sessions) > maxAgentSessionsPosted {
		writeJSONError(w, http.StatusBadRequest, "too many sessions in one report")
		return
	}
	n, err := s.store.RecordAgentSessions(req.Sessions, time.Now().UTC())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": n})
}

// agentSessionBlocks is what this endpoint enforces against agent sessions.
// Nothing at all unless the policy enforces and names the endpoint, and it is
// still a lab machine now: a role or address can change after the policy was
// saved, and telemetry rewrites both.
func (s *Server) agentSessionBlocks(endpointID string) []string {
	t := s.store.GetDetectionTuning()
	policy := t.AgentEgressPolicy
	if policy.Mode != storage.EgressEnforce || !policy.BlocksOn(endpointID) || s.egressBlockRefusal(t, endpointID) != nil {
		return nil
	}
	return policy.BlockEntries(endpointID)
}

// egressBlockTargetsLab refuses a change that would hold blocks on a machine
// that is not a lab machine. Blocking is only proven on a throwaway lab guest; a
// block on a machine agents work from can stop the work itself. Lab addresses are
// read from before the save, so one save can't name a machine and call it lab. A
// save that leaves the blocks alone isn't asked: a machine leaving the lab must
// not stop unrelated edits, and it stops receiving blocks by itself.
func (s *Server) egressBlockTargetsLab(before, after storage.DetectionTuning) error {
	a, b := before.AgentEgressPolicy, after.AgentEgressPolicy
	if a.Mode == b.Mode && slices.Equal(a.BlockEndpoints, b.BlockEndpoints) {
		return nil
	}
	for _, id := range b.BlockEndpoints {
		if err := s.egressBlockRefusal(before, id); err != nil {
			return err
		}
	}
	return nil
}

// egressBlockRefusal says why an endpoint may not hold blocks. An explicit role
// wins over the address, as it does for every other role decision.
func (s *Server) egressBlockRefusal(t storage.DetectionTuning, id string) error {
	ep, err := s.store.GetEndpoint(id)
	if err != nil || ep == nil || ep.ID != id {
		return fmt.Errorf("%w: agent egress blocks: no endpoint with the id %q", storage.ErrInvalidDetectionTuning, id)
	}
	switch strings.ToLower(strings.TrimSpace(ep.RoleTag)) {
	case storage.RoleLab:
		return nil
	case storage.RoleAgent, storage.RoleInfra, storage.RolePersonal:
	default:
		if t.IsLabAddress(ep.IP) {
			return nil
		}
	}
	return fmt.Errorf("%w: agent egress blocks: %s is not a lab machine, and blocks are only held on lab machines", storage.ErrInvalidDetectionTuning, id)
}
