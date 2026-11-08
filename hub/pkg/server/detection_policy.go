package server

// One choke point for every write to detection policy: tuning saves, the
// shipped-values reset, "Expected" on a finding, the exclusions and each host's
// retirement. A change is applied at once, recorded in the audit with what
// changed, and the floor drill runs on the result; ClampToFloor keeps a saved
// value from going below the floor, and the Aico push counts the changes.
//
// The credential a change came through (api-key, jwt or console) is recorded
// with it. It is a label, not proof of who acted: the admin key can mint any
// hub identity.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ominull/hub/pkg/detector"
	"ominull/hub/pkg/storage"
)

const policyChangedAudit = "DETECTION_POLICY_CHANGED"

// policyChange is one write to detection policy.
type policyChange struct {
	policy  string // "detection_tuning", "exclusion", or "endpoint_watch"
	op      string
	target  string // "detection:tuning", "exclusion:<id>", or "endpoint:<id>"
	before  any    // the saved policy (nil for a new exclusion)
	after   any    // the policy the change saves
	wording string // what changed, for the audit row
}

// drillFailed is the one entry a drill that could not run sends; the
// authority shows it as such, not as a blinded case.
const drillFailed = "the drill could not run"

// drillMaxShown is the most cases the hub accepts in one payload.
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

// notePolicyChange records an applied change for the audit trail and for the
// Aico push's detection-policy note.
func (s *Server) notePolicyChange(r *http.Request, c policyChange) {
	s.audit(r, policyChangedAudit, c.target, fmt.Sprintf("changed %s %s: %s; credential %s (unverified)",
		strings.ReplaceAll(c.policy, "_", " "), c.op, c.wording, credentialOf(r)))
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
		wording: tuningDelta(before, after),
	}
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
	for _, e := range page.Entries {
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
		parts = append(parts, plural(len(changes), "detection policy change", "detection policy changes")+" in the last 24 h")
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

// ruleSummary is one line for an audit entry.
func ruleSummary(r storage.ExpectedRule) string {
	what := strings.Join(r.Kinds(), ", ")
	if what == "" {
		what = "nothing"
	}
	return r.ID + " (" + what + ")"
}
