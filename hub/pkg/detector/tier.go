package detector

import (
	"encoding/json"

	"ominull/hub/pkg/storage"
)

// huntTypes are the behavioural detectors whose findings are hunt leads, never
// alerts (storage/anomaly_tier.go). Every other detector pages: canary and
// decoy hits, silence and return against expected presence, sweeps, threat
// intelligence, beaconing, volume and the agent egress rules.
//
// Their code stays: the plan retires them from paging only, and deletes them
// only after labelled drills compare both tiers.
var huntTypes = map[string]bool{
	"NOVEL_DESTINATION": true,
}

// TierFor names the tier a detector's findings belong to.
func TierFor(anomalyType string) string {
	if huntTypes[anomalyType] {
		return storage.TierHunt
	}
	return storage.TierPage
}

// applyTier stamps a hunt lead: held as a hunt lead, the tier in its evidence,
// and on an agent-heavy endpoint (named in the tuning by id or role, or
// observed running an agent runtime; never judged by operating system) its
// severity lowered to LOW with the
// detector's own severity kept beside it.
func applyTier(a *storage.AnomalyAlert, ep storage.Endpoint, cfg storage.DetectionTuning, runsAgents func() bool) {
	if TierFor(a.AnomalyType) != storage.TierHunt {
		return
	}
	a.HeldReason = storage.HeldHunt
	fields := map[string]any{}
	if a.Evidence != "" && json.Unmarshal([]byte(a.Evidence), &fields) != nil {
		fields = nil // evidence that is not an object is kept as written
	}
	if fields != nil {
		fields["tier"] = storage.TierHunt
	}
	if cfg.IsAgentHeavy(ep) || (cfg.AgentHeavyObserved && runsAgents != nil && runsAgents()) {
		if fields != nil {
			fields["detector_severity"] = a.Severity
			fields["muted"] = storage.MutedAgentHeavy
		}
		a.Severity = "LOW"
	}
	if fields != nil {
		if raw, err := json.Marshal(fields); err == nil {
			a.Evidence = string(raw)
		}
	}
}
