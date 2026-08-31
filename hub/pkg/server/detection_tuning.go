package server

import (
	"encoding/json"
	"net/http"
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
	add("learning period", before.WarmupHours, after.WarmupHours)
	add("quiet processes", len(before.QuietProcesses), len(after.QuietProcesses))
	add("quiet networks", len(before.QuietOrgs), len(after.QuietOrgs))
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
