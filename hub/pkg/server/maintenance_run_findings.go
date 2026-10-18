package server

// Per-run attention records for Nightshift: a supervised run that waits on a
// window (needs_hands), stopped making progress (stalled) or failed gets its
// own feed record, ominull.run.<endpoint>.<package>, so Nightshift's planner
// can wake a steward for it. At most runRecordsMax are open at once (the
// neediest first). A record that clears (a later run succeeded, the job
// ended) reads resolved for runResolvedFor, then drops; the raised set is a
// settings row so a hub restart does not leave Nightshift holding stale ones.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"ominull/hub/pkg/scripts"
)

const (
	runRecordsSetting = "maintenance.run_records"
	runRecordsMax     = 20
	runResolvedFor    = 24 * time.Hour
	runFailedFor      = 24 * time.Hour // a failed run older than this is history, not news
)

var runRecordsMu sync.Mutex

type runRecordSeen struct {
	Title      string     `json:"title"`
	RaisedAt   time.Time  `json:"raised_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

type runAttentionItem struct {
	uid      string
	rank     int // 0 needs_hands, 1 stalled, 2 failed
	since    time.Time
	severity int
	message  string
	resource feedResource
	unmapped map[string]any
}

// feedSafe lowercases a value and keeps only letters, digits, - and _.
func feedSafe(v string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, strings.ToLower(v))
}

// runUID: ominull.run.<endpoint>.<package>, feed-safe.
func runUID(endpointID, pkg string) string {
	return "ominull.run." + feedSafe(endpointID) + "." + feedSafe(pkg)
}

// runNextMove says what a steward (or the owner) should do about the run.
func runNextMove(state, jobID string) string {
	switch state {
	case "needs_hands":
		return "take a steward remote-screen session for run " + jobID + " and click the dialog"
	case "stalled":
		return "check the machine: run " + jobID + " has made no progress; cancel it (ominullctl maint cancel " + jobID + ") if it is stuck"
	}
	return "read the run's output (ominullctl maint wait " + jobID + "), then fix the cause or run it again"
}

func (s *Server) runAttentionItems(now time.Time) ([]runAttentionItem, error) {
	if s.scriptsStore == nil || s.responseStore == nil {
		return nil, nil
	}
	eps, err := s.store.ListEndpoints("")
	if err != nil {
		return nil, err
	}
	libraries := map[string][]*scripts.Script{}
	var out []runAttentionItem
	for _, ep := range eps {
		if ep.Status == "retired" {
			continue
		}
		list, ok := libraries[ep.TenantID]
		if !ok {
			if list, err = s.scriptsStore.ListScripts(ep.TenantID); err != nil {
				return nil, err
			}
			libraries[ep.TenantID] = list
		}
		latest, err := s.responseStore.LatestScriptJobs(ep.TenantID, ep.ID)
		if err != nil {
			return nil, err
		}
		for _, sc := range list {
			job := latest[sc.ID]
			if job == nil {
				continue
			}
			name := sc.Name
			if m := sc.Package(); m != nil && m.Package != "" {
				name = m.Package
			}
			run := s.liveRun(job, now)
			it := runAttentionItem{uid: runUID(ep.ID, name), since: job.RequestedAt}
			switch run.State {
			case "needs_hands":
				it.rank, it.severity = 0, ocsfSevLow
			case "stalled":
				it.rank, it.severity = 1, ocsfSevLow
			case "failed":
				if run.CompletedAt == nil || now.Sub(*run.CompletedAt) > runFailedFor {
					continue
				}
				it.rank, it.severity, it.since = 2, ocsfSevMedium, *run.CompletedAt
			default:
				continue
			}
			if run.Progress != nil && !run.Progress.PhaseSince.IsZero() {
				it.since = run.Progress.PhaseSince
			}
			host := ep.Hostname
			if host == "" {
				host = ep.ID
			}
			what := map[string]string{"needs_hands": "is waiting on a window", "stalled": "has stalled", "failed": "failed"}[run.State]
			it.message = fmt.Sprintf("%s on %s %s", name, host, what)
			if run.Reason != "" {
				it.message += ": " + run.Reason
			}
			it.resource = feedResource{Type: "endpoint", Name: host, UID: ep.ID}
			un := map[string]any{"endpoint_id": ep.ID, "endpoint": host, "package": name, "state": run.State,
				"job_id": job.ID, "since": it.since.UTC().Format(time.RFC3339), "next_move": runNextMove(run.State, job.ID)}
			if run.Reason != "" {
				un["reason"] = run.Reason
			}
			if run.Window != nil {
				un["window"] = run.Window
			}
			if run.Mode != "" {
				un["mode"] = run.Mode
			}
			it.unmapped = un
			out = append(out, it)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].rank != out[j].rank {
			return out[i].rank < out[j].rank
		}
		return out[i].since.Before(out[j].since)
	})
	if len(out) > runRecordsMax {
		out = out[:runRecordsMax]
	}
	return out, nil
}

// runFindings: the open run records, plus resolved ones for a day.
func (s *Server) runFindings(now time.Time) ([]feedFinding, error) {
	items, err := s.runAttentionItems(now)
	if err != nil {
		return nil, err
	}
	runRecordsMu.Lock()
	defer runRecordsMu.Unlock()
	seen := map[string]runRecordSeen{}
	if raw, err := s.store.GetSetting(runRecordsSetting); err == nil && raw != "" {
		_ = json.Unmarshal([]byte(raw), &seen)
	}
	changed := false
	open := map[string]bool{}
	var out []feedFinding
	for _, it := range items {
		open[it.uid] = true
		title := "Maintenance run needs attention"
		if r, ok := seen[it.uid]; !ok || r.ResolvedAt != nil || r.Title != it.message {
			seen[it.uid] = runRecordSeen{Title: it.message, RaisedAt: now}
			changed = true
		}
		out = append(out, s.feedFinding(now, it.uid, title, it.severity, ocsfStatusNew, it.message, []feedResource{it.resource}, it.unmapped))
	}
	uids := make([]string, 0, len(seen))
	for uid := range seen {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	for _, uid := range uids {
		if open[uid] {
			continue
		}
		r := seen[uid]
		if r.ResolvedAt == nil {
			t := now
			r.ResolvedAt = &t
			seen[uid] = r
			changed = true
		}
		if now.Sub(*r.ResolvedAt) >= runResolvedFor {
			delete(seen, uid)
			changed = true
			continue
		}
		out = append(out, s.feedFinding(now, uid, "Maintenance run needs attention", ocsfSevInformational, ocsfStatusResolved,
			"Resolved: "+r.Title, nil, nil))
	}
	if changed {
		raw, _ := json.Marshal(seen)
		if len(seen) == 0 {
			raw = nil
		}
		if err := s.store.SetSetting(runRecordsSetting, string(raw)); err != nil {
			return nil, err
		}
	}
	return out, nil
}
