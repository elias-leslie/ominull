package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
	"ominull/hub/pkg/threatintel"
)

// vendorRangesOwned refuses an agent runtime vendor prefix whose ends the
// hub's network attribution places on a shared CDN or rented compute: any
// site can be fronted from there, so the range would prove nothing about the
// maker.
func vendorRangesOwned(t storage.DetectionTuning) error {
	for _, v := range t.AgentRuntimeVendors {
		for _, raw := range v.Prefixes {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			for _, a := range []netip.Addr{p.Masked().Addr(), lastAddr(p)} {
				geo := threatintel.ResolveGeoIP(a.String())
				if geo.Tenancy == storage.TenancySharedCDN || geo.Tenancy == storage.TenancyHosting {
					return fmt.Errorf("%w: agent runtime vendor prefix %s holds %s address space of %q, which any site can be served from",
						storage.ErrInvalidDetectionTuning, raw, geo.Tenancy, geo.Org)
				}
			}
		}
	}
	return nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := range b {
		bit := i * 8
		switch {
		case bit >= p.Bits():
			b[i] = 0xff
		case bit+8 > p.Bits():
			b[i] |= 0xff >> uint(p.Bits()-bit)
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

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
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		// A save is a patch over the saved tuning: a field the request leaves
		// out keeps its saved value. The console's sheet posts only the fields
		// it shows, and an API caller adding one known workload must not switch
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
			case "known_workloads":
				req.KnownWorkloads = nil
			case "agent_runtimes":
				req.AgentRuntimes = nil
			case "agent_runtime_vendors":
				req.AgentRuntimeVendors = nil
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
		err = storage.CheckNewWorkloadExpiry(before.KnownWorkloads, req.KnownWorkloads, time.Now())
		var after storage.DetectionTuning
		if err == nil {
			after, err = storage.PrepareDetectionTuning(req)
		}
		if err == nil {
			err = vendorRangesOwned(after)
		}
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

// applyTuning saves a judged tuning change: at once when it only tightens,
// after the authorization when it loosens. The caller holds policyMu.
func (s *Server) applyTuning(w http.ResponseWriter, r *http.Request, c policyChange, action string) {
	c, ok := s.tightenFirst(w, r, c)
	if !ok {
		return
	}
	approvalID, ok := s.policyAuthorized(w, r, c)
	if !ok {
		return
	}
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
	s.audit(r, action, "detection", c.wording+"; credential "+credentialOf(r)+" (unverified)")
	if c.changed() {
		s.notePolicyChange(r, c, approvalID)
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
	add("first-seen enabled", before.FirstSeenOn, after.FirstSeenOn)
	add("bandwidth enabled", before.BandwidthOn, after.BandwidthOn)
	add("bandwidth baseline size", before.BandwidthMinSamples, after.BandwidthMinSamples)
	add("learning period", before.WarmupHours, after.WarmupHours)
	add("quiet processes", len(before.QuietProcesses), len(after.QuietProcesses))
	add("quiet networks", len(before.QuietOrgs), len(after.QuietOrgs))
	add("expected clients", len(before.QuietClients), len(after.QuietClients))
	add("expected pairs", len(before.QuietPairs), len(after.QuietPairs))
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
	workloads := func(t storage.DetectionTuning) []string {
		out := make([]string, 0, len(t.KnownWorkloads))
		for _, k := range t.KnownWorkloads {
			w := k.Workload + "@" + k.Owner
			if k.IncludeRented {
				w += "+rented"
			}
			out = append(out, w+" until "+k.ExpiresAt.UTC().Format(time.RFC3339))
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
	listDelta("known workloads", workloads(before), workloads(after))
	listDelta("agent runtimes", runtimes(before), runtimes(after))
	vendors := func(t storage.DetectionTuning) []string {
		var out []string
		for _, v := range t.AgentRuntimeVendors {
			out = append(out, v.Runtime+"="+v.Vendor)
			for _, d := range v.Domains {
				out = append(out, v.Runtime+":"+d)
			}
			for _, p := range v.Prefixes {
				out = append(out, v.Runtime+":"+p)
			}
		}
		return out
	}
	listDelta("agent runtime vendors", vendors(before), vendors(after))
	listDelta("agent-heavy endpoints", before.AgentHeavyEndpoints, after.AgentHeavyEndpoints)
	listDelta("agent-heavy roles", before.AgentHeavyRoles, after.AgentHeavyRoles)
	add("agent-heavy when a runtime is seen", before.AgentHeavyObserved, after.AgentHeavyObserved)
	listDelta("admin fan-out sources", before.AdminFanoutSources, after.AdminFanoutSources)
	listDelta("admin fan-out targets", before.AdminFanoutTargets, after.AdminFanoutTargets)
	add("admin fan-out host limit", before.AdminFanoutMax, after.AdminFanoutMax)
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

	proc := storage.ProcessPathKey(finding.ProcessPath)
	owner, tenancy := destinationFromEvidence(finding.Evidence)
	if proc == "" || proc == "unknown" {
		writeJSONError(w, http.StatusBadRequest,
			"this finding has no attributed process, so there is no program to vouch for")
		return
	}
	if evidenceText(finding.Evidence, "attribution_status") == storage.AttributionPathMismatch {
		writeJSONError(w, http.StatusBadRequest,
			"the agent found this process running a different file from the one at its reported path, so that path cannot vouch for it")
		return
	}
	if storage.ValidQuietPath(proc) != nil {
		// A program in a folder any account can write to is vouched for by
		// the build the finding saw, never by where it sits.
		pinned := proc + " sha256:" + evidenceText(finding.Evidence, "executable_sha256")
		switch {
		case storage.ValidQuietPath(pinned) == nil:
			proc = pinned
		case strings.HasPrefix(proc, "/") || (len(proc) > 2 && proc[1] == ':'):
			writeJSONError(w, http.StatusBadRequest,
				"this program is in a folder any account can write to, and the agent did not record which build it was, so there is nothing safe to vouch for")
			return
		default:
			writeJSONError(w, http.StatusBadRequest,
				"this finding names the program only by its name, not where it is installed, and a name is something any program can take")
			return
		}
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

	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	before := s.store.GetDetectionTuning()
	pair := proc + "@" + owner
	for _, existing := range before.QuietPairs {
		if strings.EqualFold(strings.TrimSpace(existing), pair) {
			// Already vouched for: this only dismisses the finding, so it is
			// recorded and counted on the Nightshift feed like any other.
			if err := s.acknowledgeFinding(r, finding.ID); err != nil {
				writeJSONError(w, http.StatusInternalServerError, err.Error())
				return
			}
			s.writeSuppressed(w, pair, finding, false)
			return
		}
	}
	tuning := before
	tuning.QuietPairs = append(append([]string(nil), before.QuietPairs...), pair)
	after, err := storage.PrepareDetectionTuning(tuning)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	c := tuningChange("suppress_pair", before, after)
	approvalID, ok := s.policyAuthorized(w, r, c)
	if !ok {
		return
	}
	if _, err := s.store.SaveDetectionTuning(after, operatorName(r)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.detector != nil {
		s.detector.InvalidateTuning()
	}
	s.notePolicyChange(r, c, approvalID)
	if err := s.acknowledgeFinding(r, finding.ID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "DETECTION_PAIR_SUPPRESSED", "detection",
		fmt.Sprintf("marked %s talking to %s as expected, from finding %s on %s",
			proc, owner, finding.AnomalyType, finding.EndpointID))

	s.writeSuppressed(w, pair, finding, true)
}

// acknowledgeFinding dismisses one finding the way /anomalies/acknowledge
// does, with its audit row, so the Nightshift feed counts it.
func (s *Server) acknowledgeFinding(r *http.Request, id string) error {
	done, err := s.store.AcknowledgeFindings("", []string{id}, false)
	s.auditDismissal(r, findingsAcknowledgedAudit, "acknowledged", done)
	return err
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

// destinationFromEvidence reads the counterparty back out of the evidence the
// detector attached. The alert row carries the address; who owns it, and
// whether that owner rents the range out, lives in the evidence JSON.
func destinationFromEvidence(evidence string) (owner, tenancy string) {
	// The AS number is the owner a pair is written with; the name stands in
	// only where nothing numbered the network.
	owner = evidenceText(evidence, "destination_asn")
	if owner == "" {
		owner = evidenceText(evidence, "destination_owner")
	}
	return owner, evidenceText(evidence, "destination_tenancy")
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
