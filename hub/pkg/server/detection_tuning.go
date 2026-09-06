package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// handleDetectionTuning reads and writes the numbers the behavioural detectors
// run on.
//
// Reading is open to any authenticated operator: an analyst looking at an alert
// has to be able to see the rule that produced it, and "why did this fire?" is
// not an administrator's question. Writing is an administrator's action,
// because loosening a detector is a security decision with no other trace.
func (s *Server) handleDetectionTuning(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.writeTuning(w, s.store.GetDetectionTuning())

	case http.MethodPost, http.MethodPut:
		var req storage.DetectionTuning
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		before := s.store.GetDetectionTuning()
		by := r.Header.Get("X-Username")
		if by == "" {
			by = "admin"
		}
		saved, err := s.store.SaveDetectionTuning(req, by)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// The engine caches the row for a few seconds; drop it so the operator
		// sees their change take effect rather than wondering whether it did.
		if s.detector != nil {
			s.detector.InvalidateTuning()
		}
		s.audit(r, "DETECTION_TUNING_SAVED", "detection", tuningDelta(before, saved))
		s.writeTuning(w, saved)

	case http.MethodDelete:
		by := r.Header.Get("X-Username")
		if by == "" {
			by = "admin"
		}
		saved, err := s.store.SaveDetectionTuning(storage.DefaultDetectionTuning(), by)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if s.detector != nil {
			s.detector.InvalidateTuning()
		}
		s.audit(r, "DETECTION_TUNING_RESET", "detection", "restored the shipped thresholds")
		s.writeTuning(w, saved)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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
	add("first-seen enabled", before.FirstSeenOn, after.FirstSeenOn)
	add("bandwidth enabled", before.BandwidthOn, after.BandwidthOn)
	add("bandwidth baseline size", before.BandwidthMinSamples, after.BandwidthMinSamples)
	add("learning period", before.WarmupHours, after.WarmupHours)
	add("quiet processes", len(before.QuietProcesses), len(after.QuietProcesses))
	add("quiet networks", len(before.QuietOrgs), len(after.QuietOrgs))
	add("expected clients", len(before.QuietClients), len(after.QuietClients))
	add("expected pairs", len(before.QuietPairs), len(after.QuietPairs))
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

// handleSuppressPair turns one finding into a tuning entry.
//
// Triage without this is a dead end. An operator reading a finding they know to
// be ordinary could acknowledge it, and watch the same conversation raise the
// same finding an hour later, forever; the only way to stop it was to open the
// tuning sheet and type the pair by hand, from memory, which nobody does. This
// is the loop every alerting product has and this one did not: say "expected"
// on the alert, and the rule that produced it learns.
//
// What it will not do is as important as what it does. It silences a process
// talking to a named owner - never a destination on its own, because a CDN or
// cloud allowlist is exactly where an implant wants to be, and never a
// destination on rented compute, because anybody can rent a machine inside a
// range that sounds reputable. It refuses an unattributed process for the same
// reason: "unknown" is not something an operator can vouch for.
func (s *Server) handleSuppressPair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-Role") != "admin" {
		writeJSONError(w, http.StatusForbidden, "silencing a conversation is an administrator action")
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.ID) == "" {
		writeJSONError(w, http.StatusBadRequest, "which finding?")
		return
	}

	finding, err := s.store.GetAnomalyAlert(strings.TrimSpace(req.ID))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "no such finding")
		return
	}

	proc := processBaseName(finding.ProcessPath)
	owner, tenancy := destinationFromEvidence(finding.Evidence)
	if proc == "" || proc == "unknown" {
		writeJSONError(w, http.StatusBadRequest,
			"this finding has no attributed process, so there is no program to vouch for")
		return
	}
	if owner == "" {
		writeJSONError(w, http.StatusBadRequest,
			"nothing has named this destination's network, and an address on its own is not a counterparty worth silencing")
		return
	}
	if tenancy == storage.TenancyHosting {
		writeJSONError(w, http.StatusBadRequest,
			"that destination is rented compute, which anyone can buy inside; silence the process and the owner it should be talking to instead")
		return
	}

	tuning := s.store.GetDetectionTuning()
	pair := proc + "@" + owner
	for _, existing := range tuning.QuietPairs {
		if strings.EqualFold(strings.TrimSpace(existing), pair) {
			_ = s.store.AcknowledgeAnomaly(finding.ID)
			s.writeSuppressed(w, pair, finding, false)
			return
		}
	}
	tuning.QuietPairs = append(tuning.QuietPairs, pair)

	by := r.Header.Get("X-Username")
	if by == "" {
		by = "admin"
	}
	if _, err := s.store.SaveDetectionTuning(tuning, by); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.detector != nil {
		s.detector.InvalidateTuning()
	}
	if err := s.store.AcknowledgeAnomaly(finding.ID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "DETECTION_PAIR_SUPPRESSED", "detection",
		fmt.Sprintf("marked %s talking to %s as expected, from finding %s on %s",
			proc, owner, finding.AnomalyType, finding.EndpointID))

	s.writeSuppressed(w, pair, finding, true)
}

func (s *Server) writeSuppressed(w http.ResponseWriter, pair string, finding storage.AnomalyAlert, added bool) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"pair":         pair,
		"added":        added,
		"acknowledged": finding.ID,
		"endpoint_id":  finding.EndpointID,
		"anomaly_type": finding.AnomalyType,
	})
}

// processBaseName reduces a path to the program's own name, the way the
// detectors match on it.
func processBaseName(path string) string {
	p := strings.TrimSpace(path)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return strings.ToLower(p)
}

// destinationFromEvidence reads the counterparty back out of the evidence the
// detector attached. The alert row carries the address; who owns it, and
// whether that owner rents the range out, lives in the evidence JSON.
func destinationFromEvidence(evidence string) (owner, tenancy string) {
	if strings.TrimSpace(evidence) == "" {
		return "", ""
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(evidence), &fields); err != nil {
		return "", ""
	}
	text := func(key string) string {
		if v, ok := fields[key].(string); ok {
			return strings.ToLower(strings.TrimSpace(v))
		}
		return ""
	}
	return text("destination_owner"), text("destination_tenancy")
}
