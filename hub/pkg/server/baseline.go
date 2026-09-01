package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"ominull/hub/pkg/storage"
)

// The baseline isolation policy, and the gate that reads it.
//
// Isolation cuts a host off and leaves a small set of permits underneath. Two of
// those permits used to be written into the agents - DNS to any resolver, DHCP
// to any server - which meant the most important question about an isolation
// ("what can this host still reach?") had an answer nobody could see or change.
//
// Now the answer is a policy: named services, named destinations, authored in
// the console. The hub resolves it per endpoint and hands the agent exactly that
// set. Two things stay compiled in and are not listed here - the hub pinhole and
// loopback - because they are what make an isolation reversible, and an
// allow-list an operator can accidentally empty is a way to lose a host.
//
// The gate is the other half. An endpoint reports the services it actually uses;
// if the baseline does not cover them, isolating it is refused with the
// uncovered list in the body, and the override is a separate audited action.

// baselineRequestLimit caps a policy submission. A policy is a short list of
// addresses; anything larger is a mistake or an attempt at one.
const baselineRequestLimit = 256 * 1024

// readinessStaleAfter is how old an endpoint's self-report may be before the
// gate stops trusting it. Agents heartbeat every few seconds, so this is
// generous - it is sized to outlast a hub restart or a rolling release, not to
// be tight.
const readinessStaleAfter = 10 * time.Minute

func (s *Server) handleBaselineCatalogue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"services": storage.BaselineCatalogue(),
	})
}

// handleBaselinePolicies lists policies and saves them. Saving replaces the
// whole rule set of one policy: an allow-list applied halfway is the failure
// this design exists to avoid, so there is no per-rule patch route.
func (s *Server) handleBaselinePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		policies, err := s.store.ListBaselinePolicies()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"policies": policies,
			"services": storage.BaselineCatalogue(),
		})

	case http.MethodPost:
		var p storage.BaselinePolicy
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, baselineRequestLimit)).Decode(&p); err != nil {
			writeJSONError(w, http.StatusBadRequest, "unreadable request body")
			return
		}
		if err := s.store.SaveBaselinePolicy(&p); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.auditBaseline(r, "BASELINE_POLICY_SAVE", p.ID,
			fmt.Sprintf("Baseline policy %q (%s) saved with %d rule(s)", p.Name, p.Scope, len(p.Rules)))
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "saved", "policy": p})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBaselinePolicyDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "unreadable request body")
		return
	}
	if err := s.store.DeleteBaselinePolicy(req.ID); err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	s.auditBaseline(r, "BASELINE_POLICY_DELETE", req.ID, "Baseline policy deleted")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": req.ID})
}

// handleBaselineEndpoint answers "what would isolating this host actually do?"
// - the exact rule set that would be applied, what the endpoint reports using,
// and anything in the second list that is missing from the first.
func (s *Server) handleBaselineEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	endpointID := strings.TrimSpace(r.URL.Query().Get("endpoint_id"))
	if endpointID == "" {
		writeJSONError(w, http.StatusBadRequest, "endpoint_id: required")
		return
	}
	if !s.endpointInScope(w, r, endpointID) {
		return
	}
	res, err := s.store.ResolveBaseline(endpointID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	ready, why, warning := s.isolationReadiness(res)
	wire, _ := storage.CapBaselineWireRules(storage.BaselineWireRules(res.Rules))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"resolution": res,
		// The same expansion the agent is handed, not a second one written for
		// the screen. A console that computes "udp/53" itself is a console that
		// can disagree with the thing doing the enforcing.
		"wire":    wire,
		"ready":   ready,
		"blocker": why,
		"warning": warning,
		// The two permits an operator cannot remove, stated rather than
		// implied. Somebody reading this screen is deciding whether a host they
		// cut off can be got back.
		"always_permitted": []map[string]string{
			{"what": "hub pinhole", "why": "the only path by which this isolation can be lifted"},
			{"what": "loopback", "why": "local software talking to itself"},
		},
	})
}

// handleBaselinePropose turns what an endpoint observed into rules an operator
// can edit and approve. It returns them; it does not save them.
func (s *Server) handleBaselinePropose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		EndpointID string `json:"endpoint_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "unreadable request body")
		return
	}
	if !s.endpointInScope(w, r, req.EndpointID) {
		return
	}
	res, err := s.store.ResolveBaseline(req.EndpointID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	proposed := storage.ProposeBaselineRules(res.Observed)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"endpoint_id": req.EndpointID,
		"rules":       proposed,
		"observed":    res.Observed,
		// Named so the console can offer "save as a policy for this host" with
		// something already in the box.
		"suggested_name": "Baseline for " + req.EndpointID,
	})
}

// isolationReadiness decides whether the hub will isolate this endpoint without
// an explicit override, and says why not in words an operator can act on. The
// third return is a warning: something worth saying that is not worth refusing
// over.
//
// An endpoint that has never answered is deliberately *not* refused. Reporting
// readiness and honouring the baseline arrive in the same agent release and are
// the same code path, so an endpoint that has not reported is an endpoint still
// running the compiled-in floor - DNS and DHCP to any destination. Isolating it
// is exactly as safe as it was before this policy existed, and refusing would
// take the Isolate button away from the whole fleet for the length of a rollout,
// during which the only way to contain a host would be an override that means
// nothing. Anyone splitting those two into separate releases has to revisit
// this: the coupling is what makes it sound.
func (s *Server) isolationReadiness(res storage.BaselineResolution) (bool, string, string) {
	if !res.ReadinessReported {
		return true, "", "This endpoint's agent predates the readiness check, so it enforces the built-in floor - DNS and DHCP to any destination - and the baseline policy does not apply to it. Isolating it is as safe as it was before, and no safer. Update the agent to bring it under the policy."
	}
	if age := time.Since(res.Readiness.ReportedAt); age > readinessStaleAfter {
		return false, fmt.Sprintf("The endpoint's last readiness report is %s old, so it describes a host that may no longer exist in that state.", age.Round(time.Minute)), ""
	}
	if ok, why := res.Readiness.Ready(); !ok {
		return false, "The endpoint reported that it is not ready to be isolated - " + why + ".", ""
	}
	if full := storage.BaselineWireRules(res.Rules); len(full) > storage.BaselineWireLimit {
		return false, fmt.Sprintf(
			"The policies covering this host expand to %d rules and an agent can hold %d, so isolating it would apply the first %d and drop the rest. Narrow the baseline that covers this host.",
			len(full), storage.BaselineWireLimit, storage.BaselineWireLimit), ""
	}
	if len(res.Uncovered) > 0 {
		parts := make([]string, 0, len(res.Uncovered))
		for _, o := range res.Uncovered {
			parts = append(parts, o.Service+" to "+o.Destination)
		}
		return false, "The baseline does not cover services this host is actually using: " + strings.Join(parts, ", ") +
			". Isolating it would cut those off. Add them to a baseline policy, or override deliberately.", ""
	}
	return true, "", ""
}

// guardIsolation is the gate in front of every isolate route. It returns false
// when the caller should stop; it has already written the response by then.
//
// The refusal is a 409 with the uncovered list in the body rather than a warning
// in a log, because the failure it prevents is not recoverable from the console:
// a host that loses DNS, DHCP or its management path under an isolation is a
// host that needs someone standing in front of it.
func (s *Server) guardIsolation(w http.ResponseWriter, r *http.Request, endpointID string, force bool) bool {
	res, err := s.store.ResolveBaseline(endpointID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "endpoint_id: "+err.Error())
		return false
	}
	ready, why, warning := s.isolationReadiness(res)
	if ready {
		if warning != "" {
			s.auditBaseline(r, "ISOLATE_HOST_UNVERIFIED", endpointID, warning)
		}
		return true
	}
	if force {
		// An operator containing a host that is actively compromised must never
		// be blocked by a stale probe. The override is allowed and it is a
		// different action in the audit log, with the reason it overrode.
		s.auditBaseline(r, "ISOLATE_HOST_FORCED", endpointID,
			"Isolation readiness overridden. "+why)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":       why,
		"endpoint_id": endpointID,
		"uncovered":   res.Uncovered,
		"observed":    res.Observed,
		"rules":       res.Rules,
		"readiness":   res.Readiness,
		// Named explicitly so a caller does not have to guess how to proceed.
		"override": `re-send with "force": true to isolate anyway; it is recorded as a separate action`,
	})
	return false
}

func (s *Server) auditBaseline(r *http.Request, action, resource, details string) {
	_ = s.store.RecordAudit(storage.AuditEntry{
		ID:        uuid.New().String(),
		TenantID:  r.Header.Get("X-Tenant-ID"),
		UserID:    r.Header.Get("X-User-ID"),
		Username:  r.Header.Get("X-Username"),
		Action:    action,
		Resource:  resource,
		Details:   details,
		IPAddress: clientIP(r),
		Timestamp: time.Now().UTC(),
	})
}

// baselineWriteGuard lets anyone authenticated read the policy list and admits
// only an administrator to write it. One route serves both because the console
// screen is one screen: an analyst deciding whether to isolate a host has to be
// able to see what an isolation would still permit, and hiding it from them
// would mean the person making the call is the one person who cannot see the
// rules. Authoring is another matter - a rule here is a standing hole in every
// isolation its scope covers.
func (s *Server) baselineWriteGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			requireAdmin(next)(w, r)
			return
		}
		next(w, r)
	}
}
