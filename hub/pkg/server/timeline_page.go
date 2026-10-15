package server

import (
	"net/http"
	"sort"
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
	HostName  string
	RangeName string
	Zone      string
	Days      []timelineDay
	Count     int
	Truncated bool
	Problems  []string
}

func (s *Server) handleTimelinePage(w http.ResponseWriter, r *http.Request) {
	viewer, ok := s.requirePageViewer(w, r)
	if !ok {
		return
	}
	body := s.buildTimeline(r.URL.Query().Get("endpoint"), r.URL.Query().Get("range"), time.Now())
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
	sort.Slice(endpoints, func(i, j int) bool { return strings.ToLower(endpoints[i].Hostname) < strings.ToLower(endpoints[j].Hostname) })
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
	for _, e := range page.Entries {
		if host != nil && !auditConcerns(e, host.ID, related) {
			continue
		}
		items = append(items, auditTimelineItem(e, names))
	}

	sort.SliceStable(items, func(i, j int) bool { return items[i].At.After(items[j].At) })
	if len(items) > timelineShown {
		items = items[:timelineShown]
		body.Truncated = true
	}
	body.Count = len(items)
	for _, it := range items {
		local := it.At.In(loc)
		it.Clock = local.Format("15:04")
		label := local.Format("Monday, January 2")
		if n := len(body.Days); n == 0 || body.Days[n-1].Label != label {
			body.Days = append(body.Days, timelineDay{Label: label})
		}
		body.Days[len(body.Days)-1].Items = append(body.Days[len(body.Days)-1].Items, it)
	}
	return body
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
// the host, or one of the host's sessions, jobs or bundles. Owner approvals
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

// auditKinds groups audit actions by what an operator would call them.
var auditKinds = []struct{ prefix, kind, tone string }{
	{"AUTO_ISOLATE", "Containment", "crit"},
	{"ISOLATE", "Containment", "crit"},
	{"UNISOLATE", "Containment", "ok"},
	{"MESH_", "Containment", "warn"},
	{"TERMINAL_", "Terminal", "info"},
	{"OWNER_APPROVAL_", "Approval", "info"},
	{"EVIDENCE_", "Evidence", "info"},
	{"RESPONSE_", "Response", "info"},
	{"SCRIPT_", "Response", "info"},
	{"ANOMAL", "Finding", "ok"},
	{"CONSOLE_SIGNIN", "Sign-in", "idle"},
}

func auditTimelineItem(e storage.AuditEntry, names map[string]string) timelineItem {
	it := timelineItem{At: e.Timestamp, Kind: "Change", Tone: "idle", Title: auditTitle(e.Action), Who: e.Username, Detail: e.Details}
	for _, k := range auditKinds {
		if strings.HasPrefix(e.Action, k.prefix) {
			it.Kind, it.Tone = k.kind, k.tone
			break
		}
	}
	if name, ok := names[e.Resource]; ok {
		it.Host, it.HostID = name, e.Resource
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
