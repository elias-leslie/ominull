package detector

import (
	"encoding/json"
	"log"
	"sort"
	"strings"

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
	"OFF_HOURS_ACTIVITY":   true,
	"NOVEL_PROCESS_EGRESS": true,
	"NOVEL_DESTINATION":    true,
}

// TierFor names the tier a detector's findings belong to.
func TierFor(anomalyType string) string {
	if huntTypes[anomalyType] {
		return storage.TierHunt
	}
	return storage.TierPage
}

// tierOfFinding is TierFor for a recorded finding. The subnet sweep writes
// its new-device findings (ids alert-disc-*) under NOVEL_DESTINATION without
// passing through the detector; they are not behavioural and keep paging.
func tierOfFinding(a storage.AnomalyAlert) string {
	if strings.HasPrefix(a.ID, "alert-disc-") {
		return storage.TierPage
	}
	return TierFor(a.AnomalyType)
}

// HuntTypes lists the hunt-tier detector types, sorted.
func HuntTypes() []string {
	out := make([]string, 0, len(huntTypes))
	for t := range huntTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// applyTier stamps a hunt lead: held as a hunt lead, the tier in its evidence,
// and on an agent-heavy endpoint its severity lowered to LOW with the
// detector's own severity kept beside it.
func applyTier(a *storage.AnomalyAlert, ep storage.Endpoint, cfg storage.DetectionTuning) {
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
	if cfg.IsAgentHeavy(ep) {
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

// backfillHuntTier moves findings recorded before the tiers existed, once.
func (e *Engine) backfillHuntTier() {
	n, err := e.store.BackfillHuntTier(HuntTypes())
	if err != nil {
		log.Printf("[-] moving earlier behavioural findings to hunt leads failed: %v", err)
		return
	}
	if n > 0 {
		log.Printf("[*] moved %d earlier behavioural findings to hunt leads", n)
	}
}
