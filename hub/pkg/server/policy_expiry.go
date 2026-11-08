package server

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// An expected rule with an expiry lapses on its own (a workload rule at most
// 90 days ahead).
// That is on purpose, but one nobody meant to drop brings its false alarms
// back the day it lapses. The feed says so beforehand, so an agent renews it
// in the daily pass instead of someone remembering a date.
const (
	// policyExpiryWarnDaysSetting is the hub setting holding how many days
	// before an expected rule lapses the feed starts warning.
	policyExpiryWarnDaysSetting = "policy_expiry_warn_days"
	policyExpiryWarnDaysDefault = 30
	policyExpiryWarnDaysMin     = 1
	policyExpiryWarnDaysMax     = 89 // under the 90-day lifetime, or every new row would warn at once
	// A lapsed row is still named for this long, so a missed renewal does not
	// just vanish from the feed the moment it matters.
	policyExpiryLapsedShown = 7 * 24 * time.Hour
)

// policyExpiryWarn is how long before a lapse the feed warns.
func (s *Server) policyExpiryWarn() time.Duration {
	days := policyExpiryWarnDaysDefault
	if v, err := s.store.GetSetting(policyExpiryWarnDaysSetting); err == nil && strings.TrimSpace(v) != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			days = min(max(n, policyExpiryWarnDaysMin), policyExpiryWarnDaysMax)
		}
	}
	return time.Duration(days) * 24 * time.Hour
}

// policyExpiryFinding tells Nightshift which expected rules lapse within policy_expiry_warn_days (or lapsed in the last week),
// with how to renew each. Renewing is audited like any
// rule change; deciding whether a row is still wanted is the
// agent's job, so the finding is medium (a daily item), never a page.
func (s *Server) policyExpiryFinding(now time.Time) (feedFinding, error) {
	const uid, title = "ominull.detection.expiring", "Expected rules expiring"
	warn := s.policyExpiryWarn()
	type item struct {
		kind, name string
		expires    time.Time
	}
	var due []item
	next := item{}
	consider := func(it item) {
		if it.expires.IsZero() || now.Sub(it.expires) > policyExpiryLapsedShown {
			return
		}
		if it.expires.After(now) && (next.expires.IsZero() || it.expires.Before(next.expires)) {
			next = it
		}
		if it.expires.Sub(now) < warn {
			due = append(due, it)
		}
	}
	for _, r := range s.store.GetDetectionTuning().ExpectedRules {
		consider(item{"expected_rule", r.ID, r.ExpiresAt})
	}
	warnDays := int(warn.Hours() / 24)
	unmapped := map[string]any{"warn_days": warnDays}
	if len(due) == 0 {
		msg := "No expected rule expires within " + plural(warnDays, "day", "days")
		if !next.expires.IsZero() {
			msg += fmt.Sprintf("; the next, %s %s, expires in %s", strings.ReplaceAll(next.kind, "_", " "), next.name, plural(daysLeft(next.expires, now), "day", "days"))
		}
		return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved, msg, nil, unmapped), nil
	}
	sort.Slice(due, func(i, j int) bool { return due[i].expires.Before(due[j].expires) })
	rows := make([]map[string]any, 0, len(due))
	lapsed := 0
	for _, d := range due {
		if !d.expires.After(now) {
			lapsed++
		}
		if len(rows) < feedDismissedListShown {
			rows = append(rows, map[string]any{"kind": d.kind, "name": d.name,
				"expires_at": d.expires.UTC().Format(time.RFC3339), "days_left": daysLeft(d.expires, now)})
		}
	}
	unmapped["expiring"] = rows
	if len(due) > len(rows) {
		unmapped["expiring_omitted"] = len(due) - len(rows)
	}
	what := plural(len(due), "expected rule", "expected rules")
	how := "re-POST the rule to /api/v1/detection/expected, same id and fields, later expires_at"
	verb := " expire"
	if len(due) == 1 {
		verb = " expires"
	}
	soon := due[0]
	when := fmt.Sprintf("soonest: %s in %s", soon.name, plural(daysLeft(soon.expires, now), "day", "days"))
	if lapsed > 0 {
		when = fmt.Sprintf("%d already lapsed, %s %s ago", lapsed, soon.name, plural(-daysLeft(soon.expires, now), "day", "days"))
	}
	msg := fmt.Sprintf("%s within %d days (%s). Renew if still wanted: %s", what+verb, warnDays, when, how)
	return s.feedFinding(now, uid, title, ocsfSevMedium, ocsfStatusNew, msg, nil, unmapped), nil
}
