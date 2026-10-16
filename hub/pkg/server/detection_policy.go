package server

// One choke point for every write to detection policy: tuning saves, the
// shipped-values reset, "Expected" on a finding, learning proposals, the
// exclusions, each host's presence and retirement (which decide whether
// the silence floor reports it), and opening a learning window (which holds
// the behavioural findings of every host it covers). Each change is compared field by field with what is saved now.
// One that only tightens applies at once and leaves a note for Nightshift. One
// that loosens anything waits for the owner's passkey tap, through the same
// response-authority approval isolation uses: the admin key, a console session
// and a JWT minted from the admin key can all ask, and none of them can make
// it happen. The authority's statement shows the owner the field-level diff,
// and its digest binds the exact before and after, so an approval granted
// against one saved policy is refused once that policy has changed.
//
// The credential a change came through (api-key, jwt or console) is recorded
// with it. It is a label, not proof of who acted: the admin key can mint any
// hub identity.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

const policyChangedAudit = "DETECTION_POLICY_CHANGED"

// policyChange is one write to detection policy, judged before it is applied.
type policyChange struct {
	policy  string // "detection_tuning", "exclusion", "endpoint_watch" or "learning_window"
	op      string // see responseauth's detectionPolicyOps
	target  string // "detection:tuning", "exclusion:<id>", "endpoint:<id>" or "learning:<scope_type>:<scope_id>"
	before  any    // the saved policy (nil for a new exclusion)
	after   any    // the policy the change would save
	loosens []string
	wording string // what changed, for the audit row and the note
	// tightenedFirst is the tightening half of a mixed change, already
	// saved, so the owner is asked about the loosening alone.
	tightenedFirst string
}

// payload is what the authority digests and describes. Both sides build it
// the same way from the same before and after, so a retried request whose
// saved policy has not moved yields the same digest.
func (c policyChange) payload() ([]byte, error) {
	before, err := json.Marshal(c.before)
	if err != nil {
		return nil, err
	}
	after, err := json.Marshal(c.after)
	if err != nil {
		return nil, err
	}
	// The authority accepts only canonical JSON (sorted keys, as decoded and
	// encoded again), so the struct field order cannot leak into it.
	if before, err = canonicalJSON(before); err != nil {
		return nil, err
	}
	if after, err = canonicalJSON(after); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]interface{}{
		"policy": c.policy, "op": c.op,
		"before": json.RawMessage(before), "after": json.RawMessage(after),
	})
}

// credentialOf names how the caller authenticated. Unverified: whoever holds
// the admin key can present any of these.
func credentialOf(r *http.Request) string {
	switch m := r.Header.Get("X-Auth-Method"); m {
	case "api-key", "jwt", "console":
		return m
	}
	return "unknown"
}

// policyApproved lets a change through when it loosens nothing, or when the
// owner has approved exactly this change. Otherwise it answers the request
// itself (202 with the approval to wait for, or the refusal) and returns false.
func (s *Server) policyApproved(w http.ResponseWriter, r *http.Request, c policyChange) (string, bool) {
	if len(c.loosens) == 0 {
		return "", true
	}
	if s.responseAuth == nil {
		writeJSONError(w, http.StatusServiceUnavailable,
			"this change loosens detection ("+strings.Join(c.loosens, ", ")+"), which needs the owner's approval, and the response authority that asks for it is not available")
		return "", false
	}
	payload, err := c.payload()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the change could not be described: "+err.Error())
		return "", false
	}
	tenantID := s.tenantFromRequest(r)
	if tenantID == "" {
		tenantID = "default"
	}
	requester := s.operatorFromRequest(r) + " (" + credentialOf(r) + ")"
	id := strings.TrimSpace(r.Header.Get(approvalHeader))
	if id == "" {
		v, err := s.responseAuth.RequestApproval(r.Context(), &responseauth.ApprovalRequestInput{
			TenantID: tenantID, Requester: requester, Kind: responseauth.ActionKindDetection,
			Summary: c.wording, Targets: []string{c.target}, Payload: payload,
		})
		if err != nil {
			s.audit(r, "OWNER_APPROVAL_UNAVAILABLE", c.target, "detection policy: "+err.Error())
			writeJSONError(w, approvalStatus(err), "this change loosens detection ("+strings.Join(c.loosens, ", ")+") and the owner's approval could not be requested: "+err.Error())
			return "", false
		}
		s.approvalWake.notify()
		s.audit(r, "OWNER_APPROVAL_REQUESTED", c.target, fmt.Sprintf("%s (approval %s): %s", v.Action, v.ID, v.Summary))
		body := map[string]interface{}{
			"approval_id": v.ID,
			"state":       v.State,
			"action":      v.Action,
			"summary":     v.Summary,
			"targets":     v.Targets,
			"loosens":     c.loosens,
			"expires_at":  v.ExpiresAt,
			"next":        "This change loosens detection, so the owner approves it on their phone. Poll GET /api/v1/approvals?id=" + v.ID + "&wait=20, then repeat this request with header " + approvalHeader + ".",
		}
		if c.tightenedFirst != "" {
			body["tightened_now"] = c.tightenedFirst
		}
		writeJSON(w, http.StatusAccepted, body)
		return "", false
	}
	sum := sha256.Sum256(payload)
	if _, err := s.responseAuth.ConsumeApproval(r.Context(), &responseauth.ApprovalConsumeRequest{
		ID: id, TenantID: tenantID, Requester: requester, Kind: responseauth.ActionKindDetection,
		Digest: hex.EncodeToString(sum[:]), Targets: []string{c.target},
	}); err != nil {
		s.audit(r, "OWNER_APPROVAL_REFUSED", c.target, fmt.Sprintf("detection policy with approval %s: %v", id, err))
		status := approvalStatus(err)
		if status == http.StatusNotFound {
			status = http.StatusForbidden
		}
		writeJSONError(w, status, "owner approval not valid for this change: "+err.Error()+
			". If the saved policy changed since the approval was asked for, ask again.")
		return "", false
	}
	s.approvalWake.notify()
	s.audit(r, "OWNER_APPROVAL_USED", c.target, "detection policy change under approval "+id)
	return id, true
}

// notePolicyChange records an applied change for the audit trail and for the
// Nightshift feed's detection-policy note.
func (s *Server) notePolicyChange(r *http.Request, c policyChange, approvalID string) {
	how := "tightened"
	if approvalID != "" {
		how = "loosened (" + strings.Join(c.loosens, ", ") + ") with owner approval " + approvalID
	}
	s.audit(r, policyChangedAudit, c.target, fmt.Sprintf("%s %s %s: %s; credential %s (unverified)",
		how, strings.ReplaceAll(c.policy, "_", " "), c.op, c.wording, credentialOf(r)))
}

// Acknowledging or deleting findings takes them out of the Nightshift feed's
// open counts, so each one is recorded and the feed's detection-policy note
// counts them: a finding hidden before the feed read it still shows there.
const (
	findingsAcknowledgedAudit = "FINDINGS_ACKNOWLEDGED"
	findingsClearedAudit      = "FINDINGS_CLEARED"
)

func (s *Server) auditDismissal(r *http.Request, action, verb string, d storage.Dismissal) {
	if d.Count == 0 {
		return
	}
	types := ""
	if len(d.HighTypes) > 0 {
		types = " (" + strings.Join(d.HighTypes, ", ") + ")"
	}
	s.audit(r, action, "findings", fmt.Sprintf("%s %s, %d HIGH or CRITICAL%s; credential %s (unverified)",
		verb, plural(d.Count, "finding", "findings"), d.High, types, credentialOf(r)))
}

// dismissalCounts reads back what auditDismissal wrote: findings and how many
// of them were HIGH or CRITICAL.
func dismissalCounts(details, verb string) (n, high int) {
	_, _ = fmt.Sscanf(details, verb+" %d", &n)
	if i := strings.Index(details, ", "); i >= 0 {
		_, _ = fmt.Sscanf(details[i+2:], "%d", &high)
	}
	return n, high
}

// tuningChange judges a tuning write. Both sides are compared as saved,
// without the bookkeeping fields.
func tuningChange(op string, before, after storage.DetectionTuning) policyChange {
	before.UpdatedAt, before.UpdatedBy = time.Time{}, ""
	after.UpdatedAt, after.UpdatedBy = time.Time{}, ""
	return policyChange{
		policy: "detection_tuning", op: op, target: "detection:tuning",
		before: before, after: after,
		loosens: tuningLoosens(before, after),
		wording: tuningDelta(before, after),
	}
}

// tightenFirst splits a tuning change that tightens some fields and loosens
// others. The tightening half needs nobody, so it is saved now and noted; the
// change returned carries only the loosening, which is all the owner is asked
// about. A list that loses some entries and gains others loses them now. The
// caller holds policyMu; false means the request has been answered.
func (s *Server) tightenFirst(w http.ResponseWriter, r *http.Request, c policyChange) (policyChange, bool) {
	before, okB := c.before.(storage.DetectionTuning)
	after, okA := c.after.(storage.DetectionTuning)
	if len(c.loosens) == 0 || !okB || !okA {
		return c, true
	}
	loose := map[string]bool{}
	for _, k := range c.loosens {
		loose[k] = true
	}
	a, b := tuningFields(before), tuningFields(after)
	mid := tuningFields(before)
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	for k := range keys {
		dir := tuningDirections[k]
		takeAfter := !loose[k]
		if dir == windowField {
			takeAfter = !loose["off_hours_window"]
		}
		switch {
		case takeAfter:
			if v, ok := b[k]; ok {
				mid[k] = v
			} else {
				delete(mid, k)
			}
		case dir == addLoosens:
			mid[k] = keptEntries(a[k], b[k])
		}
	}
	var half storage.DetectionTuning
	raw, err := json.Marshal(mid)
	if err == nil {
		err = json.Unmarshal(raw, &half)
	}
	if err == nil {
		half, err = storage.PrepareDetectionTuning(half)
	}
	if err == nil && len(tuningLoosens(before, half)) > 0 {
		err = fmt.Errorf("it would loosen %s", strings.Join(tuningLoosens(before, half), ", "))
	}
	if err != nil {
		writeJSONError(w, http.StatusConflict, "this change tightens some settings and loosens others ("+strings.Join(c.loosens, ", ")+
			"), and its tightening part cannot be saved on its own ("+err.Error()+"); save the tightening and the loosening as separate changes")
		return c, false
	}
	tight := tuningChange(c.op, before, half)
	if !tight.changed() {
		return c, true
	}
	if _, err := s.store.SaveDetectionTuning(half, operatorName(r)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return c, false
	}
	if s.detector != nil {
		s.detector.InvalidateTuning()
	}
	s.notePolicyChange(r, tight, "")
	rest := tuningChange(c.op, s.store.GetDetectionTuning(), after)
	rest.tightenedFirst = tight.wording
	return rest, true
}

// keptEntries is the list before without the entries after drops.
func keptEntries(before, after any) any {
	list, ok := before.([]any)
	if !ok {
		return before
	}
	has := map[string]bool{}
	if next, ok := after.([]any); ok {
		for _, x := range next {
			raw, _ := json.Marshal(x)
			has[string(raw)] = true
		}
	}
	kept := []any{}
	for _, x := range list {
		raw, _ := json.Marshal(x)
		if has[string(raw)] {
			kept = append(kept, x)
		}
	}
	return kept
}

// changed reports whether a change changes anything at all.
func (c policyChange) changed() bool {
	a, _ := json.Marshal(c.before)
	b, _ := json.Marshal(c.after)
	return string(a) != string(b)
}

// How a change to one tuning field reads. Every field the row saves is named
// here (TestEveryTuningFieldKnowsWhichWayLoosens); a field that is not is
// judged as loosening.
type tuningDirection int

const (
	ignored       tuningDirection = iota // bookkeeping
	offLoosens                           // switching it off loosens
	onLoosens                            // switching it on loosens
	higherLoosens                        // a larger number loosens
	lowerLoosens                         // a smaller number loosens
	addLoosens                           // a list entry that was not there loosens
	anyLoosens                           // any change loosens
	windowField                          // the off-hours window, judged as a whole
)

var tuningDirections = map[string]tuningDirection{
	"updated_at": ignored, "updated_by": ignored,

	"off_hours_start": windowField, "off_hours_end": windowField, "off_hours_zone": windowField,
	"off_hours_enabled": offLoosens,

	"beacon_enabled":              offLoosens,
	"beacon_min_samples":          higherLoosens,
	"beacon_min_span_minutes":     higherLoosens,
	"beacon_min_interval_seconds": higherLoosens,
	"beacon_max_interval_seconds": lowerLoosens,
	"beacon_score_threshold":      higherLoosens,
	"beacon_cooldown_minutes":     higherLoosens,

	"first_seen_enabled":          offLoosens,
	"first_seen_cooldown_minutes": higherLoosens,
	"bandwidth_enabled":           offLoosens,
	"bandwidth_cooldown_minutes":  higherLoosens,
	"bandwidth_min_samples":       higherLoosens,
	"silence_enabled":             offLoosens,
	"silence_after_minutes":       higherLoosens,
	"warmup_hours":                higherLoosens,

	"quiet_processes": addLoosens,
	"quiet_orgs":      addLoosens,
	"quiet_clients":   addLoosens,
	"quiet_pairs":     addLoosens,
	"container_cidrs": addLoosens,
	"known_workloads": addLoosens,

	"agent_egress_enabled":  offLoosens,
	"agent_runtimes":        anyLoosens, // a runtime named is also muted where it runs
	"agent_baseline_days":   higherLoosens,
	"agent_upload_floor_mb": higherLoosens,
	"agent_upload_factor":   higherLoosens,
	"agent_heavy_endpoints": addLoosens,
	"agent_heavy_roles":     addLoosens,
	"agent_heavy_observed":  onLoosens,

	"admin_fanout_sources":   addLoosens,
	"admin_fanout_targets":   addLoosens,
	"admin_fanout_max_hosts": higherLoosens,
}

// tuningLoosens names each field whose change loosens detection; empty means
// the change only tightens, or changes nothing.
func tuningLoosens(before, after storage.DetectionTuning) []string {
	a, b := tuningFields(before), tuningFields(after)
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	var out []string
	window := false
	for k := range keys {
		if reflect.DeepEqual(a[k], b[k]) {
			continue
		}
		dir, known := tuningDirections[k]
		if !known {
			out = append(out, k)
			continue
		}
		loose := false
		switch dir {
		case ignored:
		case windowField:
			window = true
		case offLoosens:
			loose = a[k] == true && b[k] != true
		case onLoosens:
			loose = a[k] != true && b[k] == true
		case higherLoosens, lowerLoosens:
			x, okA := a[k].(float64)
			y, okB := b[k].(float64)
			loose = !okA || !okB || (dir == higherLoosens && y > x) || (dir == lowerLoosens && y < x)
		case addLoosens:
			loose = addsEntries(a[k], b[k])
		default:
			loose = true
		}
		if loose {
			out = append(out, k)
		}
	}
	if window && !windowCovers(after, before) {
		out = append(out, "off_hours_window")
	}
	sort.Strings(out)
	return out
}

func tuningFields(t storage.DetectionTuning) map[string]any {
	raw, _ := json.Marshal(t)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// addsEntries reports a list that gained an entry: a longer list, or one the
// same length holding something the old one did not.
func addsEntries(before, after any) bool {
	had := map[string]bool{}
	if list, ok := before.([]any); ok {
		for _, x := range list {
			raw, _ := json.Marshal(x)
			had[string(raw)] = true
		}
	} else if before != nil {
		return true
	}
	list, ok := after.([]any)
	if !ok {
		return after != nil
	}
	for _, x := range list {
		raw, _ := json.Marshal(x)
		if !had[string(raw)] {
			return true
		}
	}
	return false
}

// windowCovers reports whether the new off-hours window still holds every
// hour of the old one, in the same zone. Another zone is a different window.
func windowCovers(after, before storage.DetectionTuning) bool {
	if !strings.EqualFold(strings.TrimSpace(after.OffHoursZone), strings.TrimSpace(before.OffHoursZone)) {
		return false
	}
	hours := func(t storage.DetectionTuning) [24]bool {
		var h [24]bool
		for i := 0; i < 24; i++ {
			if t.OffHoursStart < t.OffHoursEnd {
				h[i] = i >= t.OffHoursStart && i < t.OffHoursEnd
			} else if t.OffHoursStart > t.OffHoursEnd {
				h[i] = i >= t.OffHoursStart || i < t.OffHoursEnd
			}
		}
		return h
	}
	was, now := hours(before), hours(after)
	for i := range was {
		if was[i] && !now[i] {
			return false
		}
	}
	return true
}

// exclusionView is an exclusion as the owner approves it: without the time it
// happens to be written at, and without an id the hub has yet to pick.
func exclusionView(ex storage.Exclusion, keepID bool) storage.Exclusion {
	ex.CreatedAt = time.Time{}
	if !keepID {
		ex.ID = ""
	}
	return ex
}

// detectionPolicySection is the Nightshift feed's view of detection policy: a
// CRITICAL finding while the saved tuning row is unsound, and an informational
// note listing the day's changes, each with the credential it came through.
func (s *Server) detectionPolicySection(now time.Time) ([]feedFinding, error) {
	var out []feedFinding
	const invalidUID, invalidTitle = "ominull.detection.invalid", "Detection policy unsound"
	if problem := s.store.DetectionTuningProblem(); problem != "" {
		out = append(out, s.feedFinding(now, invalidUID, invalidTitle, ocsfSevCritical, ocsfStatusNew,
			"The hub's saved detection tuning is unsound; fix or re-save it in the console", nil,
			map[string]any{"problem": problem}))
	} else {
		out = append(out, s.feedFinding(now, invalidUID, invalidTitle, ocsfSevInformational, ocsfStatusResolved,
			"The saved detection tuning is sound", nil, nil))
	}

	page, err := s.store.AuditHistory("", 50, "", storage.AuditFilter{Action: policyChangedAudit, From: now.Add(-feedAnomalyWindow)})
	if err != nil {
		return out, err
	}
	const uid, title = "ominull.detection.changes", "Detection policy changes"
	changes := make([]map[string]any, 0, len(page.Entries))
	loosened := 0
	for _, e := range page.Entries {
		if strings.HasPrefix(e.Details, "loosened") {
			loosened++
		}
		changes = append(changes, map[string]any{"at": e.Timestamp.UTC().Format(time.RFC3339), "by": e.Username, "target": e.Resource, "change": e.Details})
	}
	dismissed := []map[string]any{}
	acked, deleted, high := 0, 0, 0
	for _, kind := range []struct{ action, verb string }{{findingsAcknowledgedAudit, "acknowledged"}, {findingsClearedAudit, "deleted"}} {
		page, err := s.store.AuditHistory("", 50, "", storage.AuditFilter{Action: kind.action, From: now.Add(-feedAnomalyWindow)})
		if err != nil {
			return out, err
		}
		for _, e := range page.Entries {
			n, h := dismissalCounts(e.Details, kind.verb)
			if kind.action == findingsAcknowledgedAudit {
				acked, high = acked+n, high+h
			} else {
				deleted += n
			}
			dismissed = append(dismissed, map[string]any{"at": e.Timestamp.UTC().Format(time.RFC3339), "by": e.Username, "change": e.Details})
		}
	}
	unmapped := map[string]any{"window_hours": int(feedAnomalyWindow.Hours()), "changes": changes, "dismissed": dismissed}
	if len(changes) == 0 && len(dismissed) == 0 {
		out = append(out, s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
			"No detection policy changes in the last 24 h", nil, unmapped))
		return out, nil
	}
	var parts []string
	if len(changes) > 0 {
		parts = append(parts, fmt.Sprintf("%s in the last 24 h (%d loosened with the owner's approval, %d tightened)",
			plural(len(changes), "detection policy change", "detection policy changes"), loosened, len(changes)-loosened))
	}
	if len(dismissed) > 0 {
		parts = append(parts, fmt.Sprintf("%s acknowledged (%d HIGH or CRITICAL) and %d acknowledged findings deleted in the last 24 h",
			plural(acked, "finding", "findings"), high, deleted))
	}
	out = append(out, s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusNew, strings.Join(parts, "; "), nil, unmapped))
	return out, nil
}
