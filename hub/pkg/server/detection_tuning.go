package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// retiredTuningKeys are the lists expected rules replaced. A save naming one
// is refused, so a caller written for them learns it instead of seeing a
// silent no-op.
var retiredTuningKeys = map[string]bool{
	"quiet_processes": true, "quiet_orgs": true, "quiet_clients": true, "quiet_pairs": true,
	"known_workloads": true, "agent_runtime_vendors": true,
	"admin_fanout_sources": true, "admin_fanout_targets": true, "admin_fanout_max_hosts": true,
}

// handleDetectionTuning reads and writes the numbers the behavioural detectors
// run on.
//
// Reading is open to any authenticated operator: an analyst looking at an alert
// has to be able to see the rule that produced it, and "why did this fire?" is
// not an administrator's question. Writing is an administrator's action,
// because loosening a detector is a security decision with no other trace.
//
// A save is a patch over what is saved (sending expected_rules replaces the whole
// list), applies at once, is audited with a detection-policy note and is drilled, the
// verdict going on ominull.detection.drill. An invalid draft or one over 16 KiB is
// refused with the reason. Check a change with the replay route first (cut is the
// share of recorded findings it silences).
func (s *Server) handleDetectionTuning(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.writeTuning(w, s.store.GetDetectionTuning())

	case http.MethodPost, http.MethodPut:
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		// A save is a patch over the saved tuning: a field the request leaves
		// out keeps its saved value. The console's sheet posts only the fields
		// it shows, and an API caller adding one expected rule must not switch
		// every detector off; a body that decoded onto zero values did exactly
		// that once (beacon, first-seen, bandwidth, silence and the quiet lists
		// all went to false and empty). A list in the request replaces the saved
		// one. List fields of structs are cleared before decoding, so a shorter
		// list cannot inherit fields from the saved entries it overwrites.
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(raw, &keys); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		for k := range keys {
			if retiredTuningKeys[strings.ToLower(k)] {
				writeJSONError(w, http.StatusBadRequest, k+" is retired: say what is expected with an expected rule (POST /api/v1/detection/expected)")
				return
			}
		}
		s.policyMu.Lock()
		defer s.policyMu.Unlock()
		before := s.store.GetDetectionTuning()
		// A deep copy: decoding into lists shared with before would rewrite
		// the before side of the audit delta.
		var req storage.DetectionTuning
		if blob, err := json.Marshal(before); err != nil || json.Unmarshal(blob, &req) != nil {
			writeJSONError(w, http.StatusInternalServerError, "the saved tuning could not be read")
			return
		}
		for k := range keys {
			switch strings.ToLower(k) {
			case "expected_rules":
				req.ExpectedRules = nil
			case "agent_runtimes":
				req.AgentRuntimes = nil
			case "agent_egress_policy":
				var nested map[string]json.RawMessage
				_ = json.Unmarshal(keys[k], &nested)
				for n := range nested {
					switch strings.ToLower(n) {
					case "rules":
						req.AgentEgressPolicy.Rules = nil
					case "block_endpoints":
						req.AgentEgressPolicy.BlockEndpoints = nil
					}
				}
			}
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !req.SilenceOn {
			writeJSONError(w, http.StatusBadRequest, "silence detection is part of the floor and cannot be switched off: a host that stops reporting blinds every other detector")
			return
		}
		after, err := s.prepareRules(before, req)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.applyTuning(w, r, tuningChange("save", before, after), "DETECTION_TUNING_SAVED")

	case http.MethodDelete:
		s.policyMu.Lock()
		defer s.policyMu.Unlock()
		// A reset tightens only when it silences a subset of what it
		// replaces: shipped quiet entries someone removed come back with it.
		s.applyTuning(w, r, tuningChange("reset", s.store.GetDetectionTuning(), storage.DefaultDetectionTuning()), "DETECTION_TUNING_RESET")

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// applyTuning saves a tuning change. The caller holds policyMu.
func (s *Server) applyTuning(w http.ResponseWriter, r *http.Request, c policyChange, action string) {
	saved, err := s.store.SaveDetectionTuning(c.after.(storage.DetectionTuning), operatorName(r))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, storage.ErrInvalidDetectionTuning) {
			status = http.StatusBadRequest
		}
		writeJSONError(w, status, err.Error())
		return
	}
	// The engine caches the row for a few seconds; drop it so the operator
	// sees their change take effect rather than wondering whether it did.
	if s.detector != nil {
		s.detector.InvalidateTuning()
	}
	s.refreshDomainFeedsIfChanged(c.before, saved)
	s.audit(r, action, "detection", c.wording+"; credential "+credentialOf(r)+" (unverified)")
	if c.changed() {
		s.notePolicyChange(r, c)
	}
	s.writeTuning(w, saved)
}

// writeTuning sends the settings alongside the shipped defaults, so the console
// can show what each number was before anyone touched it without keeping its
// own copy that drifts from this one.
func (s *Server) writeTuning(w http.ResponseWriter, t storage.DetectionTuning) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"tuning":   t,
		"defaults": storage.DefaultDetectionTuning(),
		"zone":     t.Location().String(),
		"window":   t.OffHoursLabel(),
		"now":      time.Now().In(t.Location()).Format("15:04 MST"),
	})
}

// tuningDelta names what actually changed, so the audit entry is readable
// without diffing two JSON blobs by eye.
func tuningDelta(before, after storage.DetectionTuning) string {
	var parts []string
	add := func(name string, a, b interface{}) {
		if a != b {
			parts = append(parts, name)
		}
	}
	add("off-hours window", before.OffHoursLabel(), after.OffHoursLabel())
	add("off-hours enabled", before.OffHoursOn, after.OffHoursOn)
	add("beacon enabled", before.BeaconOn, after.BeaconOn)
	add("beacon threshold", before.BeaconScore, after.BeaconScore)
	add("beacon samples", before.BeaconMinSamples, after.BeaconMinSamples)
	add("beacon span", before.BeaconMinSpanMin, after.BeaconMinSpanMin)
	add("beacon interval band", before.BeaconMinInterval*100000+before.BeaconMaxInterval, after.BeaconMinInterval*100000+after.BeaconMaxInterval)
	add("beacon cooldown", before.BeaconCooldownMin, after.BeaconCooldownMin)
	add("bandwidth enabled", before.BandwidthOn, after.BandwidthOn)
	add("learning period", before.WarmupHours, after.WarmupHours)
	listDelta := func(name string, a, b []string) {
		had := map[string]bool{}
		for _, x := range a {
			had[x] = true
		}
		has := map[string]bool{}
		for _, x := range b {
			has[x] = true
		}
		var added, removed []string
		for _, x := range b {
			if !had[x] {
				added = append(added, "+"+x)
			}
		}
		for _, x := range a {
			if !has[x] {
				removed = append(removed, "-"+x)
			}
		}
		if d := append(added, removed...); len(d) > 0 {
			parts = append(parts, name+" ("+strings.Join(d, " ")+")")
		}
	}
	rules := func(t storage.DetectionTuning) []string {
		out := make([]string, 0, len(t.ExpectedRules))
		for _, r := range t.ExpectedRules {
			w := ruleSummary(r)
			if !r.ExpiresAt.IsZero() {
				w += " until " + r.ExpiresAt.UTC().Format(time.RFC3339)
			}
			out = append(out, w)
		}
		return out
	}
	runtimes := func(t storage.DetectionTuning) []string {
		out := make([]string, 0, len(t.AgentRuntimes))
		for _, r := range t.AgentRuntimes {
			out = append(out, r.Name+"="+r.Path)
		}
		return out
	}
	listDelta("expected rules", rules(before), rules(after))
	listDelta("agent runtimes", runtimes(before), runtimes(after))
	listDelta("agent egress rules", before.AgentEgressPolicy.Summaries(), after.AgentEgressPolicy.Summaries())
	// The first match wins, so a reorder alone is a change.
	if a, b := before.AgentEgressPolicy.Summaries(), after.AgentEgressPolicy.Summaries(); !slices.Equal(a, b) {
		if sa, sb := slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)); slices.Equal(sa, sb) {
			parts = append(parts, "agent egress rules reordered")
		}
	}
	listDelta("agent egress block endpoints", before.AgentEgressPolicy.BlockEndpoints, after.AgentEgressPolicy.BlockEndpoints)
	add("agent egress mode", before.AgentEgressPolicy.Mode, after.AgentEgressPolicy.Mode)
	listDelta("agent-heavy endpoints", before.AgentHeavyEndpoints, after.AgentHeavyEndpoints)
	listDelta("agent-heavy roles", before.AgentHeavyRoles, after.AgentHeavyRoles)
	add("agent-heavy when a runtime is seen", before.AgentHeavyObserved, after.AgentHeavyObserved)
	add("agent egress enabled", before.AgentEgressOn, after.AgentEgressOn)
	add("agent baseline days", before.AgentBaselineDays, after.AgentBaselineDays)
	add("agent upload floor", before.AgentUploadFloorMB, after.AgentUploadFloorMB)
	add("agent upload factor", before.AgentUploadFactor, after.AgentUploadFactor)
	add("container networks", strings.Join(before.ContainerCIDRs, ","), strings.Join(after.ContainerCIDRs, ","))
	add("silence threshold (minutes)", before.SilenceAfterMinutes, after.SilenceAfterMinutes)
	add("silence detection", before.SilenceOn, after.SilenceOn)
	if len(parts) == 0 {
		return "saved with no change"
	}
	out := "changed: "
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// detectionTuningGate lets any authenticated operator read the thresholds and
// admits only an administrator to change them. Wrapping the whole route in
// requireAdmin would hide the rule from the person the alert is shown to.
func (s *Server) detectionTuningGate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "changing a detector's thresholds is an administrator action")
		return
	}
	s.handleDetectionTuning(w, r)
}

// acknowledgeFinding dismisses one finding the way /anomalies/acknowledge
// does, with its audit row, so the Aico push counts it.
func (s *Server) acknowledgeFinding(r *http.Request, id string) error {
	done, err := s.store.AcknowledgeFindings("", []string{id}, false)
	s.auditDismissal(r, findingsAcknowledgedAudit, "acknowledged", done)
	return err
}

// evidenceText reads one string field of a finding's evidence, lower-cased.
func evidenceText(evidence, key string) string {
	var fields map[string]any
	if err := json.Unmarshal([]byte(evidence), &fields); err != nil {
		return ""
	}
	if v, ok := fields[key].(string); ok {
		return strings.ToLower(strings.TrimSpace(v))
	}
	return ""
}

// operatorName is who a tuning change is saved as.
func operatorName(r *http.Request) string {
	if by := strings.TrimSpace(r.Header.Get("X-Username")); by != "" {
		return by
	}
	return "admin"
}
