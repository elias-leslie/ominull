package server

// One choke point for every write to detection policy: tuning saves, the
// shipped-values reset, "Expected" on a finding, the exclusions, and each
// host's presence and retirement (which decide whether the silence floor
// reports it). Each change is compared field by field with what is saved now.
// One that only tightens applies at once and leaves a note for Nightshift. One
// that loosens anything is authorized by the response authority and recorded
// in the audit with a note for Nightshift, through the same authorization
// isolation uses. The authority's statement carries the field-level diff, and
// its digest binds the exact before and after, so an authorization granted
// against one saved policy is refused once that policy has changed.
//
// The credential a change came through (api-key, jwt or console) is recorded
// with it. It is a label, not proof of who acted: the admin key can mint any
// hub identity.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/detector"
	"ominull/hub/pkg/responseauth"
	"ominull/hub/pkg/storage"
)

const policyChangedAudit = "DETECTION_POLICY_CHANGED"

// policyChange is one write to detection policy, judged before it is applied.
type policyChange struct {
	policy  string // "detection_tuning", "exclusion", or "endpoint_watch"
	op      string // see responseauth's detectionPolicyOps
	target  string // "detection:tuning", "exclusion:<id>", or "endpoint:<id>"
	before  any    // the saved policy (nil for a new exclusion)
	after   any    // the policy the change would save
	loosens []string
	wording string // what changed, for the audit row and the note
	// tightenedFirst is the tightening half of a mixed change, already
	// saved, so the owner is asked about the loosening alone.
	tightenedFirst string
	// drill is the floor drill run against the policy the change would save:
	// the floor cases it would blind (empty when none). drilled says the drill
	// ran; only tuning and exclusion changes reach the floor rules.
	drill   []string
	drilled bool
	// subject names what the change loosens in the caller's errors and the
	// 202 body; empty means detection.
	subject string
}

func (c policyChange) loosensWhat() string {
	if c.subject != "" {
		return c.subject
	}
	return "detection"
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
	if c.policy == "detection_tuning" {
		// Only what moved is digested and shown: the whole tuning, rules
		// included, is more than the authority takes.
		if before, after, err = changedOnly(before, after); err != nil {
			return nil, err
		}
	}
	body := map[string]interface{}{
		"policy": c.policy, "op": c.op,
		"before": json.RawMessage(before), "after": json.RawMessage(after),
	}
	if c.drilled {
		// The owner sees what the change would blind before tapping.
		body["drill"] = append([]string{}, c.drill...)
	}
	return json.Marshal(body)
}

// changedOnly cuts two canonical tuning objects down to their difference: a
// key that did not move is dropped from both, and a list keeps only the
// entries the other side lacks.
func changedOnly(before, after []byte) ([]byte, []byte, error) {
	var a, b map[string]any
	if err := json.Unmarshal(before, &a); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(after, &b); err != nil {
		return nil, nil, err
	}
	entries := func(v any) map[string]bool {
		out := map[string]bool{}
		list, _ := v.([]any)
		for _, x := range list {
			raw, _ := json.Marshal(x)
			out[string(raw)] = true
		}
		return out
	}
	only := func(v any, other map[string]bool) []any {
		list, _ := v.([]any)
		out := []any{}
		for _, x := range list {
			if raw, _ := json.Marshal(x); !other[string(raw)] {
				out = append(out, x)
			}
		}
		return out
	}
	for k := range a {
		if reflect.DeepEqual(a[k], b[k]) {
			delete(a, k)
			delete(b, k)
			continue
		}
		_, aList := a[k].([]any)
		_, bList := b[k].([]any)
		if aList && bList {
			hadA, hadB := entries(a[k]), entries(b[k])
			a[k], b[k] = only(a[k], hadB), only(b[k], hadA)
		}
	}
	ra, err := json.Marshal(a)
	if err != nil {
		return nil, nil, err
	}
	rb, err := json.Marshal(b)
	if err != nil {
		return nil, nil, err
	}
	if ra, err = canonicalJSON(ra); err != nil {
		return nil, nil, err
	}
	rb, err = canonicalJSON(rb)
	return ra, rb, err
}

// drillProposed runs the floor drill against the policy a change would save
// and lists the floor cases it would blind that the saved policy does not
// (one already blinded is a CRITICAL on the feed of its own). Run again when
// the approved change is retried, it gives the same answer unless the policy
// around it moved, and then the digest no longer matches and the owner is
// asked again.
func (s *Server) drillProposed(c policyChange) ([]string, bool) {
	now := time.Now().UTC()
	var cases []detector.DrillCase
	var err error
	switch after := c.after.(type) {
	case storage.DetectionTuning:
		cases, err = detector.DrillWith(s.store, now, &after)
	default:
		return nil, false
	}
	var current []detector.DrillCase
	if err == nil {
		current, err = detector.Drill(s.store, now)
	}
	if err != nil {
		return []string{drillFailed}, true
	}
	// A case that raises today and is missing from the proposed run (removing
	// an agent runtime drops its resolver-bypass case) is blinded too.
	proposed := map[string]bool{}
	missed := []string{}
	for _, dc := range cases {
		proposed[dc.Rule] = true
	}
	already := map[string]bool{}
	for _, dc := range current {
		if judgeDrillCase(dc) != "" {
			already[dc.Rule] = true
		} else if !proposed[dc.Rule] {
			missed = append(missed, dc.Rule)
		}
	}
	for _, dc := range cases {
		if !already[dc.Rule] && judgeDrillCase(dc) != "" {
			missed = append(missed, dc.Rule)
		}
	}
	if len(missed) > drillMaxShown {
		missed = missed[:drillMaxShown]
	}
	return missed, true
}

// drillFailed is the one entry a drill that could not run sends; the
// authority shows it as such, not as a blinded case.
const drillFailed = "the drill could not run"

// drillMaxShown is the most cases the authority accepts in one payload.
const drillMaxShown = 256

// credentialOf names how the caller authenticated; relay-key is Nightshift's
// relay key, which closes findings with its verdict.
// Unverified: whoever holds the admin key can present any of these.
func credentialOf(r *http.Request) string {
	switch m := r.Header.Get("X-Auth-Method"); m {
	case "api-key", "jwt", "console", "relay-key":
		return m
	}
	return "unknown"
}

// policyAuthorized has the authority sign off a change that loosens
// detection (nothing else is asked: the hub applies the change itself, the
// authority audits it and the Aico push's detection-policy note reports
// it). A change that loosens nothing passes without the authority. It returns
// the authorization id for the audit row.
func (s *Server) policyAuthorized(w http.ResponseWriter, r *http.Request, c policyChange) (string, bool) {
	if len(c.loosens) == 0 {
		return "", true
	}
	if s.responseAuth == nil {
		writeJSONError(w, http.StatusServiceUnavailable,
			"this change loosens "+c.loosensWhat()+" ("+strings.Join(c.loosens, ", ")+") and the response authority that signs it off is not available")
		return "", false
	}
	c.drill, c.drilled = s.drillProposed(c)
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
	au, err := s.responseAuth.Authorize(r.Context(), &responseauth.AuthorizeInput{
		TenantID: tenantID, Requester: requester, Kind: responseauth.ActionKindDetection,
		Targets: []string{c.target}, Payload: payload,
	})
	if err != nil {
		s.audit(r, "ACTION_REFUSED", c.target, "detection policy: "+err.Error())
		writeJSONError(w, authorizeStatus(err), "this change loosens "+c.loosensWhat()+" ("+strings.Join(c.loosens, ", ")+") and the authority did not sign it off: "+err.Error())
		return "", false
	}
	s.audit(r, "ACTION_AUTHORIZED", c.target, fmt.Sprintf("detection policy change loosening %s (authorization %s): %s", strings.Join(c.loosens, ", "), au.ID, au.Summary))
	return au.ID, true
}

// notePolicyChange records an applied change for the audit trail and for the
// Aico push's detection-policy note.
func (s *Server) notePolicyChange(r *http.Request, c policyChange, approvalID string) {
	how := "tightened"
	if approvalID != "" {
		how = "loosened (" + strings.Join(c.loosens, ", ") + ") with authorization " + approvalID
	}
	s.audit(r, policyChangedAudit, c.target, fmt.Sprintf("%s %s %s: %s; credential %s (unverified)",
		how, strings.ReplaceAll(c.policy, "_", " "), c.op, c.wording, credentialOf(r)))
	// Every applied change is drilled at once, so one that blinds a floor
	// rule is on the feed now rather than at the next weekly run.
	s.runFloorDrill(time.Now().UTC())
}

// Acknowledging or deleting findings takes them out of the Aico push's
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

// The dismissal list on the feed note: every HIGH or CRITICAL row up to the
// larger bound, then the newest others up to the smaller.
const (
	feedDismissedListShown = 50
	feedDismissedListMax   = 500
	feedAuditPagesMax      = 200
)

// auditWindow reads every audit row of one action since from, newest first,
// following the pages; complete is false only past feedAuditPagesMax pages.
func (s *Server) auditWindow(action string, from time.Time) (entries []storage.AuditEntry, complete bool, err error) {
	cursor := ""
	for i := 0; i < feedAuditPagesMax; i++ {
		page, err := s.store.AuditHistory("", 1000, cursor, storage.AuditFilter{Action: action, From: from})
		if err != nil {
			return entries, false, err
		}
		entries = append(entries, page.Entries...)
		if page.Next == "" {
			return entries, true, nil
		}
		cursor = page.Next
	}
	return entries, false, nil
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
		case dir == removeLoosens:
			mid[k] = unionEntries(a[k], b[k])
		case dir == rulesField:
			mid[k] = keptRules(a[k], b[k])
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
	s.refreshDomainFeedsIfChanged(before, s.store.GetDetectionTuning())
	s.notePolicyChange(r, tight, "")
	rest := tuningChange(c.op, s.store.GetDetectionTuning(), after)
	rest.tightenedFirst = tight.wording
	return rest, true
}

// unionEntries is the list before with the entries after adds: the
// tightening half of a list where taking an entry away loosens.
func unionEntries(before, after any) any {
	list, _ := before.([]any)
	out := append([]any{}, list...)
	has := map[string]bool{}
	for _, x := range list {
		raw, _ := json.Marshal(x)
		has[string(raw)] = true
	}
	if next, ok := after.([]any); ok {
		for _, x := range next {
			if raw, _ := json.Marshal(x); !has[string(raw)] {
				out = append(out, x)
			}
		}
	}
	return out
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

func setOf(list []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range list {
		m[x] = true
	}
	return m
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
	rulesField                           // expected rules: a new rule, or one that covers more (ruleLoosens), loosens
	removeLoosens                        // a list entry taken away loosens
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

	"bandwidth_enabled":          offLoosens,
	"bandwidth_cooldown_minutes": higherLoosens,
	"silence_enabled":            offLoosens,
	"silence_after_minutes":      higherLoosens,
	"warmup_hours":               higherLoosens,

	"container_cidrs": addLoosens,
	"expected_rules":  rulesField,

	"agent_egress_enabled":  offLoosens,
	"agent_runtimes":        anyLoosens, // a runtime named is also muted where it runs
	"agent_baseline_days":   higherLoosens,
	"agent_upload_floor_mb": higherLoosens,
	"agent_upload_factor":   higherLoosens,
	"agent_heavy_endpoints": addLoosens,
	"agent_heavy_roles":     addLoosens,
	"agent_heavy_observed":  onLoosens,

	// Any change to a zone loosens something: a network added mutes the
	// admin and sweep rules there, one removed drops its hosts' lab escape
	// and always-on infrastructure pages.
	"lab_cidrs":               anyLoosens,
	"infra_cidrs":             anyLoosens,
	"beacon_browsers":         addLoosens,
	"beacon_page_span_min":    higherLoosens,
	"decoy_addrs":             removeLoosens,
	"decoy_names":             removeLoosens,
	"domain_intel_feeds":      removeLoosens, // a feed dropped, or its confidence changed
	"tunnel_services":         removeLoosens,
	"intel_page_confidence":   higherLoosens,
	"auto_isolate_roles":      removeLoosens,
	"page_incident_hours":     higherLoosens,
	"lan_sweep_hosts":         higherLoosens,
	"lab_escape_hosts":        higherLoosens,
	"beacon_page_score":       higherLoosens,
	"beacon_rare_devices":     lowerLoosens,
	"new_dest_upload_mb":      higherLoosens,
	"new_dest_window_min":     lowerLoosens,
	"max_plausible_rate_mbps": lowerLoosens,
	"ephemeral_port_from":     anyLoosens, // a port range decides which flows count as served
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
		case removeLoosens:
			loose = addsEntries(b[k], a[k])
		case rulesField:
			loose = rulesLoosen(a[k], b[k])
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

// detectionPolicySection is the Aico push's view of detection policy: a
// CRITICAL finding while the saved tuning row is unsound, another while the
// floor drill misses or is overdue (floor_drill.go), and an informational
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
	out = append(out, s.floorDrillFinding(now))

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
	// Every dismissal row in the window is counted, not one page of them: the
	// console acknowledges one finding per request, so a HIGH acknowledgement
	// followed by many small ones would otherwise drop out of the totals. The
	// list keeps every row that dismissed a HIGH or CRITICAL finding and fills
	// up with the newest of the rest.
	dismissed := []map[string]any{}
	acked, deleted, high, rows, omitted := 0, 0, 0, 0, 0
	partial := false
	var rest []map[string]any
	relayClosed := 0
	for _, kind := range []struct{ action, verb string }{{findingsAcknowledgedAudit, "acknowledged"}, {findingsClearedAudit, "deleted"}} {
		entries, complete, err := s.auditWindow(kind.action, now.Add(-feedAnomalyWindow))
		if err != nil {
			return out, err
		}
		partial = partial || !complete
		for _, e := range entries {
			n, h := dismissalCounts(e.Details, kind.verb)
			if kind.action == findingsAcknowledgedAudit {
				acked, high = acked+n, high+h
				if strings.Contains(e.Details, "credential relay-key ") {
					relayClosed += n
				}
			} else {
				deleted += n
			}
			rows++
			row := map[string]any{"at": e.Timestamp.UTC().Format(time.RFC3339), "by": e.Username, "change": e.Details}
			if h > 0 && len(dismissed) < feedDismissedListMax {
				dismissed = append(dismissed, row)
			} else {
				rest = append(rest, row)
			}
		}
	}
	for _, row := range rest {
		if len(dismissed) >= feedDismissedListShown {
			break
		}
		dismissed = append(dismissed, row)
	}
	omitted = rows - len(dismissed)
	unmapped := map[string]any{"window_hours": int(feedAnomalyWindow.Hours()), "changes": changes, "dismissed": dismissed}
	if omitted > 0 {
		unmapped["dismissed_omitted"] = omitted
	}
	// A closure through the relay key is recorded as the owner's answer, but
	// any admin-key holder can issue a new key, so each issuance in the window
	// is listed, and beside relay-key closures so is the issuance of the key
	// that made them, however old.
	issued, issuedComplete, err := s.auditWindow(relayKeyIssuedAudit, now.Add(-feedAnomalyWindow))
	if err != nil {
		return out, err
	}
	if len(issued) > 0 {
		// Newest first and capped like the dismissed list, so issuing keys in a
		// loop cannot push the feed past its byte budget.
		shown := issued
		if len(shown) > feedDismissedListShown {
			shown = shown[:feedDismissedListShown]
			unmapped["relay_key_issued_omitted"] = len(issued) - len(shown)
		}
		rows := make([]map[string]any, 0, len(shown))
		for _, e := range shown {
			rows = append(rows, map[string]any{"at": e.Timestamp.UTC().Format(time.RFC3339), "by": e.Username, "change": e.Details})
		}
		unmapped["relay_key_issued"] = rows
	}
	if relayClosed > 0 {
		last := issued
		if len(last) == 0 {
			page, err := s.store.AuditHistory("", 1, "", storage.AuditFilter{Action: relayKeyIssuedAudit})
			if err != nil {
				return out, err
			}
			last = page.Entries
		}
		if len(last) > 0 {
			unmapped["relay_key_last_issued"] = map[string]any{"at": last[0].Timestamp.UTC().Format(time.RFC3339), "by": last[0].Username}
		}
	}
	// The floor runs wherever the saved row is weaker (detector.ClampToFloor),
	// and an expected rule past its expiry stops matching; neither changes
	// what the console shows, so both are named here.
	saved := s.store.GetDetectionTuning()
	_, clamped := detector.ClampToFloor(saved)
	if len(clamped) > 0 {
		unmapped["floor_clamped"] = clamped
	}
	var expired []string
	for _, r := range saved.ExpectedRules {
		if r.Expired(now) {
			expired = append(expired, r.ID)
		}
	}
	if len(expired) > 0 {
		if len(expired) > feedDismissedListShown {
			unmapped["expected_rules_expired_omitted"] = len(expired) - feedDismissedListShown
			expired = expired[:feedDismissedListShown]
		}
		unmapped["expected_rules_expired"] = expired
	}
	if len(changes) == 0 && len(dismissed) == 0 && len(issued) == 0 && len(clamped) == 0 && len(expired) == 0 {
		out = append(out, s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
			"No detection policy changes in the last 24 h", nil, unmapped))
		return out, nil
	}
	var parts []string
	if len(changes) > 0 {
		parts = append(parts, fmt.Sprintf("%s in the last 24 h (%d loosened, %d tightened)",
			plural(len(changes), "detection policy change", "detection policy changes"), loosened, len(changes)-loosened))
	}
	if len(dismissed) > 0 {
		atLeast := ""
		if partial {
			atLeast = "at least "
		}
		parts = append(parts, fmt.Sprintf("%s%s acknowledged (%d HIGH or CRITICAL) and %d acknowledged findings deleted in the last 24 h",
			atLeast, plural(acked, "finding", "findings"), high, deleted))
	}
	if len(issued) > 0 {
		atLeast := ""
		if !issuedComplete {
			atLeast = "at least "
		}
		parts = append(parts, fmt.Sprintf("the Aico relay key was issued %s%s in the last 24 h, last by %s at %s; "+
			"any admin-key holder can issue it, so a closure through it since then need not be the owner's own verdict",
			atLeast, plural(len(issued), "time", "times"), issued[0].Username, issued[0].Timestamp.UTC().Format(time.RFC3339)))
	}
	if len(clamped) > 0 {
		parts = append(parts, "the saved tuning is weaker than the detection floor, which runs instead: "+strings.Join(clamped, "; "))
	}
	if n, _ := unmapped["expected_rules_expired_omitted"].(int); len(expired) > 0 {
		parts = append(parts, fmt.Sprintf("expired expected rules no longer match anything: %d; renew or remove them", len(expired)+n))
	}
	out = append(out, s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusNew, strings.Join(parts, "; "), nil, unmapped))
	return out, nil
}
