package server

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"ominull/hub/pkg/storage"
)

// The timeline answers "what happened, where": findings and the actions taken
// about them, newest first, for one host or the whole fleet. Findings come
// from anomaly_alerts, actions from the audit log. It is rendered on the hub
// and needs no script.

const (
	timelineAlertLimit = 500
	timelineAuditLimit = 1000
	timelineShown      = 500
)

var timelineRanges = []struct{ Value, Label string }{
	{"24h", "Last 24 hours"},
	{"7d", "Last 7 days"},
	{"30d", "Last 30 days"},
}

func timelineWindow(value string) (string, time.Duration) {
	switch value {
	case "7d":
		return value, 7 * 24 * time.Hour
	case "30d":
		return value, 30 * 24 * time.Hour
	}
	return "24h", 24 * time.Hour
}

type timelineItem struct {
	At     time.Time
	Clock  string
	Kind   string
	Tone   string
	Title  string
	Host   string
	HostID string
	Who    string
	Detail string
	// Repeats of the same event in a row (same kind, title, host and actor)
	// share one line: Count says how many, Since is the earliest clock and
	// Details holds their distinct details, newest first.
	Count   int
	Since   string
	Details []string
}

type timelineDay struct {
	Label string
	Items []timelineItem
}

type timelineOption struct {
	Value, Label string
	Selected     bool
}

type timelineBody struct {
	Hosts     []timelineOption
	Ranges    []timelineOption
	Kinds     []timelineOption
	HostName  string
	RangeName string
	Zone      string
	Days      []timelineDay
	Count     int
	Lines     int
	KindName  string
	events    []timelineItem
	loc       *time.Location
	Truncated bool
	Problems  []string
}

func (s *Server) handleTimelinePage(w http.ResponseWriter, r *http.Request) {
	viewer, ok := s.requirePageViewer(w, r)
	if !ok {
		return
	}
	body := s.buildTimeline(r.URL.Query().Get("endpoint"), r.URL.Query().Get("range"), time.Now())
	body.filterKind(r.URL.Query().Get("kind"))
	s.servePage(w, r, "timeline", pageData{Title: "Timeline", Operator: viewer.Email, Role: viewer.Role, Back: "alerts", Body: body})
}

func (s *Server) buildTimeline(endpointID, rangeValue string, now time.Time) timelineBody {
	rangeValue, span := timelineWindow(rangeValue)
	from := now.Add(-span)
	loc := s.store.GetDetectionTuning().Location()
	var body timelineBody
	body.Zone = loc.String()
	if body.Zone == "Local" {
		body.Zone = now.In(loc).Format("MST")
	}

	endpoints, err := s.store.ListEndpoints("")
	if err != nil {
		body.Problems = append(body.Problems, "The host list could not be read: "+err.Error())
	}
	sort.Slice(endpoints, func(i, j int) bool {
		return strings.ToLower(endpoints[i].Hostname) < strings.ToLower(endpoints[j].Hostname)
	})
	names := map[string]string{}
	var host *storage.Endpoint
	body.Hosts = append(body.Hosts, timelineOption{Value: "", Label: "All hosts", Selected: endpointID == ""})
	for i := range endpoints {
		ep := &endpoints[i]
		names[ep.ID] = ep.Hostname
		if ep.ID == endpointID {
			host = ep
		}
		body.Hosts = append(body.Hosts, timelineOption{Value: ep.ID, Label: ep.Hostname, Selected: ep.ID == endpointID})
	}
	for _, rg := range timelineRanges {
		body.Ranges = append(body.Ranges, timelineOption{Value: rg.Value, Label: rg.Label, Selected: rg.Value == rangeValue})
		if rg.Value == rangeValue {
			body.RangeName = strings.ToLower(rg.Label)
		}
	}
	if endpointID != "" && host == nil {
		body.Problems = append(body.Problems, "That host is not enrolled any more. Showing all hosts.")
		endpointID = ""
		body.Hosts[0].Selected = true
	}
	body.HostName = "all hosts"
	if host != nil {
		body.HostName = host.Hostname
	}

	var items []timelineItem
	alerts, more, err := s.store.TimelineAlerts(endpointID, from, now, timelineAlertLimit)
	if err != nil {
		body.Problems = append(body.Problems, "Findings could not be read: "+err.Error())
	}
	body.Truncated = more
	for _, a := range alerts {
		items = append(items, alertTimelineItem(a, names))
	}

	page, err := s.store.AuditHistory("", timelineAuditLimit, "", storage.AuditFilter{From: from, To: now})
	if err != nil {
		body.Problems = append(body.Problems, "Actions could not be read: "+err.Error())
	}
	if page.Next != "" {
		body.Truncated = true
	}
	related := s.timelineRelatedIDs(host)
	sessionHost := map[string]string{}
	if s.terminalMgr != nil {
		for _, ts := range s.terminalMgr.ListSessions("default") {
			sessionHost[ts.SessionID] = ts.EndpointID
		}
	}
	for _, e := range page.Entries {
		if timelineSkips[e.Action] {
			continue
		}
		if host != nil && !auditConcerns(e, host.ID, related) {
			continue
		}
		items = append(items, auditTimelineItem(e, names, sessionHost))
	}

	sort.SliceStable(items, func(i, j int) bool { return items[i].At.After(items[j].At) })
	if len(items) > timelineShown {
		items = items[:timelineShown]
		body.Truncated = true
	}
	body.events, body.loc = items, loc
	body.group("")
	return body
}

// group lays the events out by day, one line per event, and folds repeats
// that follow each other into one line. kind keeps only that kind.
func (b *timelineBody) group(kind string) {
	b.Days, b.Count, b.Lines = nil, 0, 0
	for _, it := range b.events {
		if kind != "" && it.Kind != kind {
			continue
		}
		b.Count++
		local := it.At.In(b.loc)
		it.Clock = local.Format("15:04")
		it.Since = it.Clock
		it.Count = 1
		if it.Detail != "" {
			it.Details = []string{it.Detail}
		}
		label := local.Format("Monday, January 2")
		if n := len(b.Days); n == 0 || b.Days[n-1].Label != label {
			b.Days = append(b.Days, timelineDay{Label: label})
		}
		day := &b.Days[len(b.Days)-1]
		if n := len(day.Items); n > 0 && sameTimelineEvent(day.Items[n-1], it) {
			prev := &day.Items[n-1]
			prev.Count++
			prev.Since = it.Clock
			if it.Detail != "" && !containsString(prev.Details, it.Detail) {
				prev.Details = append(prev.Details, it.Detail)
			}
			continue
		}
		day.Items = append(day.Items, it)
		b.Lines++
	}
}

func sameTimelineEvent(a, b timelineItem) bool {
	return a.Kind == b.Kind && a.Title == b.Title && a.HostID == b.HostID && a.Host == b.Host && a.Who == b.Who && a.Tone == b.Tone
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// filterKind keeps one kind of event ("Finding", "Containment", ...) and
// lists every kind present, with its count, for the filter. An unknown kind
// shows everything.
func (b *timelineBody) filterKind(kind string) {
	counts := map[string]int{}
	var order []string
	for _, it := range b.events {
		if counts[it.Kind] == 0 {
			order = append(order, it.Kind)
		}
		counts[it.Kind]++
	}
	sort.Strings(order)
	if counts[kind] == 0 {
		kind = ""
	}
	b.Kinds = []timelineOption{{Value: "", Label: "Everything", Selected: kind == ""}}
	for _, k := range order {
		b.Kinds = append(b.Kinds, timelineOption{Value: k, Label: k + " (" + strconv.Itoa(counts[k]) + ")", Selected: k == kind})
	}
	if kind != "" {
		b.KindName = strings.ToLower(kind)
		b.group(kind)
	}
}

// timelineRelatedIDs collects the ids audit entries use for things that
// belong to one host: its terminal sessions, response jobs and evidence
// bundles. Those entries name the session, job or bundle, not the host.
func (s *Server) timelineRelatedIDs(host *storage.Endpoint) map[string]bool {
	ids := map[string]bool{}
	if host == nil {
		return ids
	}
	if s.terminalMgr != nil {
		for _, ts := range s.terminalMgr.ListSessions(host.TenantID) {
			if ts.EndpointID == host.ID {
				ids[ts.SessionID] = true
			}
		}
	}
	if s.responseStore != nil {
		if jobs, err := s.responseStore.ListJobs(host.TenantID, host.ID, 100); err == nil {
			for _, j := range jobs {
				ids[j.ID] = true
			}
		}
	}
	if s.evidenceStore != nil {
		if bundles, err := s.evidenceStore.ListBundles(host.TenantID, 500); err == nil {
			for _, b := range bundles {
				if b.EndpointID == host.ID {
					ids[b.ID] = true
				}
			}
		}
	}
	return ids
}

// auditConcerns reports whether an audit entry is about this host: it names
// the host, or one of the host's sessions, jobs or bundles. Authorized actions
// name their targets as a comma-separated list.
func auditConcerns(e storage.AuditEntry, endpointID string, related map[string]bool) bool {
	if e.Resource == "" {
		return false
	}
	for _, part := range strings.Split(e.Resource, ",") {
		part = strings.TrimSpace(part)
		if part == endpointID || related[part] {
			return true
		}
	}
	return false
}

func alertTimelineItem(a storage.AnomalyAlert, names map[string]string) timelineItem {
	it := timelineItem{At: a.Timestamp, Kind: "Finding", Title: a.Title, HostID: a.EndpointID, Detail: a.Description}
	it.Host = a.Hostname
	if it.Host == "" {
		it.Host = names[a.EndpointID]
	}
	switch strings.ToUpper(a.Severity) {
	case "CRITICAL", "HIGH":
		it.Tone = "crit"
	case "MEDIUM":
		it.Tone = "warn"
	default:
		it.Tone = "info"
	}
	if a.HeldReason == storage.HeldHunt {
		it.Kind, it.Tone = "Hunt lead", "idle"
	}
	if a.Acknowledged {
		it.Who = "resolved"
	}
	return it
}

// timelineSkips are audit actions too routine to show: a phone reopening a
// terminal page writes one on every load.
var timelineSkips = map[string]bool{
	"TERMINAL_SESSION_DETACHED":   true,
	"TERMINAL_SESSION_REATTACHED": true,
}

// auditTitles names the actions whose generic title would read badly.
var auditTitles = map[string]string{
	"TERMINAL_SESSION_CREATED": "Opened a terminal",
	"TERMINAL_SESSION_CLOSED":  "Ended a terminal",
}

// auditKinds groups audit actions by what an operator would call them.
var auditKinds = []struct{ prefix, kind, tone string }{
	{"AUTO_ISOLATE", "Containment", "crit"},
	{"ISOLATE", "Containment", "crit"},
	{"UNISOLATE", "Containment", "ok"},
	{"MESH_", "Containment", "warn"},
	{"TERMINAL_", "Terminal", "info"},
	{"ACTION_", "Authorization", "info"},
	{"OWNER_APPROVAL_", "Authorization", "info"}, // rows written before approvals were retired
	{"EVIDENCE_", "Evidence", "info"},
	{"RESPONSE_", "Response", "info"},
	{"SCRIPT_", "Response", "info"},
	{"ANOMAL", "Finding", "ok"},
	{"CONSOLE_SIGNIN", "Sign-in", "idle"},
}

func auditTimelineItem(e storage.AuditEntry, names, sessionHost map[string]string) timelineItem {
	it := timelineItem{At: e.Timestamp, Kind: "Change", Tone: "idle", Title: auditTitle(e.Action), Who: e.Username, Detail: e.Details}
	if title, ok := auditTitles[e.Action]; ok {
		// Their details name the session and grant ids, not anything a
		// reader acts on; the host link says where.
		it.Title, it.Detail = title, ""
	}
	for _, k := range auditKinds {
		if strings.HasPrefix(e.Action, k.prefix) {
			it.Kind, it.Tone = k.kind, k.tone
			break
		}
	}
	resource := e.Resource
	if ep, ok := sessionHost[resource]; ok {
		resource = ep
	}
	if name, ok := names[resource]; ok {
		it.Host, it.HostID = name, resource
	}
	return it
}

// auditTitle turns ISOLATE_HOST into "Isolate host".
func auditTitle(action string) string {
	words := strings.ToLower(strings.ReplaceAll(action, "_", " "))
	if words == "" {
		return "Recorded action"
	}
	return strings.ToUpper(words[:1]) + words[1:]
}
