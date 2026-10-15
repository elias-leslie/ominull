package server

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"ominull/hub/pkg/storage"
)

// One owner approval per agent release. A request to /api/v1/agents/update
// that names canary endpoints is approved once for every endpoint it covers;
// the hub queues the canaries only and holds the rest (storage
// agent_rollouts). When every canary runs the version, is online and passes
// the native provenance check, the held endpoints are queued; a canary with a
// provenance problem, or one that has not got there by the deadline, halts
// the rollout and nothing more is queued. Agents still verify their own
// update grant: the approval signs grants for every endpoint up front, but a
// held endpoint's grant stays pending (never delivered) until the rollout is
// released, and is deleted when it halts or is superseded.

const (
	rolloutCanaryDeadline = 30 * time.Minute
	rolloutOnlineWithin   = 2 * time.Minute
	rolloutTick           = 15 * time.Second
)

// scheduleAgentUpdates queues version for every endpoint want selects (and
// granted names, when an approval limits the request) that can install it.
func (s *Server) scheduleAgentUpdates(version string, want func(storage.Endpoint) bool, granted []string) (scheduled, unsupported []map[string]string, err error) {
	ready, unsupported, err := s.planAgentUpdates(version, want, granted)
	if err != nil {
		return nil, nil, err
	}
	for _, ep := range ready {
		if err := s.store.RequestAgentUpdate(ep.ID, version); err == nil {
			scheduled = append(scheduled, map[string]string{"endpoint_id": ep.ID, "hostname": ep.Hostname, "from": ep.DriverVersion, "to": version})
		}
	}
	return scheduled, unsupported, nil
}

// planAgentUpdates sorts the selected endpoints below version into those that
// can install it and those that cannot, without queueing anything.
func (s *Server) planAgentUpdates(version string, want func(storage.Endpoint) bool, granted []string) (ready []storage.Endpoint, unsupported []map[string]string, err error) {
	endpoints, err := s.store.ListEndpoints("")
	if err != nil {
		return nil, nil, err
	}
	for _, ep := range endpoints {
		if granted != nil && !contains(granted, ep.ID) {
			continue // only what the owner approved, even for "all"
		}
		if !want(ep) || ep.Status == "retired" {
			continue
		}
		if compareVersions(ep.DriverVersion, version) >= 0 {
			continue // already up to date
		}
		pkg, selfInstallable := updatePackageFor(ep.UpdateCapability)
		if !selfInstallable {
			unsupported = append(unsupported, map[string]string{"endpoint_id": ep.ID, "hostname": ep.Hostname, "os": ep.OS, "reason": "endpoint reports no supported native package capability"})
			continue
		}
		// Refuse to queue a job for a release the endpoint could never install.
		// The agent verifies the signature itself and would reject it, so an
		// unsigned release must surface here as one clear answer rather than as
		// a queued job that quietly never completes.
		if _, _, signed := s.signedAgentPackage(version, pkg); !signed {
			unsupported = append(unsupported, map[string]string{"endpoint_id": ep.ID, "hostname": ep.Hostname, "os": ep.OS, "reason": "no signed " + agentPackageName(version, pkg) + " on the hub; sign the release with scripts/sign-release.sh and redeploy"})
			continue
		}
		if job, err := s.store.GetAgentUpdateJob(ep.ID); err == nil && job != nil && job.CompletedAt == nil && compareVersions(job.DesiredVersion, version) > 0 {
			continue // a newer update is already queued; never step it back
		}
		ready = append(ready, ep)
	}
	return ready, unsupported, nil
}

// rolloutTargets resolves what a request covers: every non-retired endpoint
// for all, else the named ones.
func (s *Server) rolloutTargets(all bool, ids []string) ([]string, error) {
	if !all {
		return sortedTargets(ids), nil
	}
	eps, err := s.store.ListEndpoints("")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ep := range eps {
		if ep.Status != "retired" {
			out = append(out, ep.ID)
		}
	}
	return sortedTargets(out), nil
}

// canaryProblem says why a canary list cannot stage this request.
func canaryProblem(canary, targets []string) string {
	for _, c := range canary {
		if !contains(targets, c) {
			return "canary " + c + " is not one of the endpoints this update covers"
		}
	}
	if len(canary) == len(targets) {
		return "every endpoint is a canary; name the canaries and leave the rest to follow"
	}
	return ""
}

// stageAgentRollout queues the canaries and holds the rest.
func (s *Server) stageAgentRollout(w http.ResponseWriter, r *http.Request, version string, all bool, ids, canary []string) {
	targets, err := s.rolloutTargets(all, ids)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if granted := grantedTargets(r); granted != nil {
		var kept []string
		for _, t := range targets {
			if contains(granted, t) {
				kept = append(kept, t)
			}
		}
		targets = kept
	}
	if p := canaryProblem(canary, targets); p != "" {
		writeJSONError(w, http.StatusBadRequest, p)
		return
	}
	var held, heldGrants []string
	for _, t := range targets {
		if !contains(canary, t) {
			held = append(held, t)
		}
	}
	for _, g := range approvalGrants(r) {
		if contains(held, g.EndpointID) {
			heldGrants = append(heldGrants, g.GrantID)
		}
	}
	isCanary := func(ep storage.Endpoint) bool { return contains(canary, ep.ID) }
	// Check every canary before queueing any: a canary that cannot install
	// proves nothing, so refuse rather than hold the fleet behind it.
	if _, unsupported, err := s.planAgentUpdates(version, isCanary, nil); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	} else if len(unsupported) > 0 {
		writeJSONError(w, http.StatusConflict, fmt.Sprintf("canary %s cannot install %s: %s", unsupported[0]["endpoint_id"], version, unsupported[0]["reason"]))
		return
	}
	ro, superseded, err := s.store.CreateAgentRollout(storage.AgentRollout{
		Version: version, AllFleet: all, Canary: canary, Held: held, HeldGrants: heldGrants, Deadline: time.Now().Add(rolloutCanaryDeadline),
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.withdrawRolloutGrants(superseded)
	scheduled, unsupported, err := s.scheduleAgentUpdates(version, isCanary, nil)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "AGENT_ROLLOUT_STAGED", ro.ID, fmt.Sprintf("Agent v%s on canary %s (%d queued); %d endpoint(s) held until the canaries are healthy, at the latest %s",
		version, strings.Join(canary, ","), len(scheduled), len(held), ro.Deadline.Format(time.RFC3339)))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"desired_version": version,
		"scheduled":       scheduled,
		"unsupported":     unsupported,
		"rollout":         ro,
	})
}

// advanceAgentRollouts releases or halts every rollout waiting on its
// canaries.
func (s *Server) advanceAgentRollouts(now time.Time) {
	active, err := s.store.AgentRollouts(true, 20)
	if err != nil {
		log.Printf("[!] agent rollouts: %v", err)
		return
	}
	for _, ro := range active {
		healthy, problem := s.canaryHealth(ro, now)
		switch {
		case problem != "":
			s.haltAgentRollout(ro, problem, now)
		case healthy:
			s.releaseAgentRollout(ro, now)
		case now.After(ro.Deadline):
			s.haltAgentRollout(ro, fmt.Sprintf("canaries did not all run v%s, online and with clean provenance, by %s", ro.Version, ro.Deadline.Format(time.RFC3339)), now)
		}
	}
}

// canaryHealth reports whether every canary is done and healthy, or a
// problem that halts the rollout now.
func (s *Server) canaryHealth(ro storage.AgentRollout, now time.Time) (bool, string) {
	for _, id := range ro.Canary {
		ep, err := s.store.GetEndpoint(id)
		if err != nil || ep == nil || ep.Status == "retired" {
			return false, "canary " + id + " is gone or retired"
		}
		if c := compareVersions(ep.DriverVersion, ro.Version); c < 0 {
			return false, ""
		} else if c > 0 {
			return false, "canary " + id + " runs v" + ep.DriverVersion + ", newer than v" + ro.Version
		}
		if reason := provenanceIssue(*ep, ro.Version); reason != "" {
			return false, "canary " + id + " runs v" + ep.DriverVersion + " but fails the native provenance check: " + reason
		}
		if now.Sub(ep.LastSeenAt) > rolloutOnlineWithin {
			return false, ""
		}
	}
	return true, ""
}

// releaseAgentRollout queues the held endpoints and delivers their grants,
// then records the rollout released. A crash before the record leaves it
// waiting, and the next tick releases it again (queueing is idempotent).
func (s *Server) releaseAgentRollout(ro storage.AgentRollout, now time.Time) {
	if ro.AllFleet {
		cur, err := s.store.GetSetting("desired_agent_version")
		if err == nil && compareVersions(ro.Version, cur) > 0 {
			if err := s.store.SetSetting("desired_agent_version", ro.Version); err != nil {
				log.Printf("[!] rollout %s: desired version not recorded: %v", ro.ID, err)
			}
		}
	}
	scheduled, unsupported, err := s.scheduleAgentUpdates(ro.Version, func(storage.Endpoint) bool { return true }, ro.Held)
	if err != nil {
		log.Printf("[!] rollout %s: queueing the held endpoints failed, retrying: %v", ro.ID, err)
		return
	}
	if err := s.store.MarkGrantsDeliverable(ro.HeldGrants); err != nil {
		log.Printf("[!] rollout %s: held grants not released, retrying: %v", ro.ID, err)
		return
	}
	if won, err := s.store.FinishAgentRollout(ro.ID, storage.RolloutReleased, "canaries healthy"); err != nil || !won {
		return
	}
	detail := fmt.Sprintf("Canaries %s run v%s with clean provenance: %d held endpoint(s) queued, %d could not self-update",
		strings.Join(ro.Canary, ","), ro.Version, len(scheduled), len(unsupported))
	_ = s.store.RecordAudit(storage.AuditEntry{ID: uuid.New().String(), Username: "hub", Action: "AGENT_ROLLOUT_RELEASED", Resource: ro.ID, Details: detail, Timestamp: now.UTC()})
}

func (s *Server) haltAgentRollout(ro storage.AgentRollout, reason string, now time.Time) {
	if won, err := s.store.FinishAgentRollout(ro.ID, storage.RolloutHalted, reason); err != nil || !won {
		return
	}
	s.withdrawRolloutGrants([]storage.AgentRollout{ro})
	_ = s.store.RecordAudit(storage.AuditEntry{ID: uuid.New().String(), Username: "hub", Action: "AGENT_ROLLOUT_HALTED", Resource: ro.ID,
		Details: fmt.Sprintf("v%s: %s; %d held endpoint(s) were not queued", ro.Version, reason, len(ro.Held)), Timestamp: now.UTC()})
}

// withdrawRolloutGrants deletes the pending grants of rollouts that ended
// without releasing their held endpoints; a grant left behind would still
// authorize that version on the endpoint.
func (s *Server) withdrawRolloutGrants(ended []storage.AgentRollout) {
	var ids []string
	for _, ro := range ended {
		ids = append(ids, ro.HeldGrants...)
	}
	if len(ids) == 0 {
		return
	}
	if err := s.store.DeleteEnforcementGrants(ids); err != nil {
		// Still pending, so never delivered; the reconcile loop withdraws
		// them (no job for the version) once the rollout no longer holds them.
		log.Printf("[!] could not withdraw %d held rollout grant(s): %v", len(ids), err)
	}
}

// supersedeAgentRollouts ends staged rollouts a newer update replaces.
func (s *Server) supersedeAgentRollouts(r *http.Request, version string) {
	ended, err := s.store.SupersedeAgentRollouts("superseded by an update to v" + version)
	if err != nil {
		log.Printf("[!] staged rollouts not superseded: %v", err)
		return
	}
	s.withdrawRolloutGrants(ended)
	for _, ro := range ended {
		s.audit(r, "AGENT_ROLLOUT_SUPERSEDED", ro.ID, fmt.Sprintf("v%s rollout replaced by an update to v%s; %d held endpoint(s) were not queued", ro.Version, version, len(ro.Held)))
	}
}

func (s *Server) agentRolloutLoop() {
	t := time.NewTicker(rolloutTick)
	defer t.Stop()
	for range t.C {
		s.advanceAgentRollouts(time.Now())
	}
}
