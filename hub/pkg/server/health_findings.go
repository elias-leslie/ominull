package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/detector"
	"ominull/hub/pkg/pki"
	"ominull/hub/pkg/storage"
)

// Health findings.
//
// The hub summarises its own state (alerts, quiet agents, certificates,
// storage, maintenance, detection health) as OCSF-shaped findings. Since
// Nightshift retired they are not pulled by anyone: aico_push.go turns them
// into Status rows and the paging alerts into notices, and an administrator
// can read the raw list at GET /api/v1/health/findings for diagnostics.
//
// The findings carry counts and states, not telemetry. Messages hold only
// counts; device names stay in the structured fields.

const (
	findingSource = "ominull"
	ocsfVersion   = "1.3.0"

	feedAnomalyWindow = 24 * time.Hour
	// An always-on server agent that has been quiet this long is a problem. A
	// laptop that is shut is not; it is listed after a week so a lost one is
	// not forgotten.
	feedServerQuiet      = 30 * time.Minute
	feedWorkstationQuiet = 7 * 24 * time.Hour
	// The gateway polls every five minutes.
	feedRouterQuiet        = 20 * time.Minute
	feedRouterCertWarnDays = 30
)

// OCSF enums used by the feed.
const (
	ocsfSevInformational = 1
	ocsfSevLow           = 2
	ocsfSevMedium        = 3
	ocsfSevHigh          = 4
	ocsfSevCritical      = 5
	ocsfStatusNew        = 1
	ocsfStatusResolved   = 4
)

func hashFeedKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// fleetAdminAuth admits a fleet administrator only: the health findings are
// fleet-wide, so an administrator scoped to one tenant is refused.
func (s *Server) fleetAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.authMiddleware(requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Tenant-ID") != "" {
			writeJSONError(w, http.StatusForbidden, "this is fleet-wide; a tenant administrator cannot use it")
			return
		}
		next(w, r)
	}))
}

type feedFinding struct {
	ClassUID    int            `json:"class_uid"`
	CategoryUID int            `json:"category_uid"`
	ActivityID  int            `json:"activity_id"`
	SeverityID  int            `json:"severity_id"`
	StatusID    int            `json:"status_id"`
	Time        int64          `json:"time"`
	Message     string         `json:"message"`
	FindingInfo map[string]any `json:"finding_info"`
	Resources   []feedResource `json:"resources,omitempty"`
	Unmapped    map[string]any `json:"unmapped,omitempty"`
	Metadata    map[string]any `json:"metadata"`
}

type feedResource struct {
	Type string `json:"type"`
	Name string `json:"name"`
	UID  string `json:"uid"`
}

func (s *Server) feedFinding(now time.Time, uid, title string, severity, status int, message string, resources []feedResource, unmapped map[string]any) feedFinding {
	return feedFinding{
		ClassUID: 2004, CategoryUID: 2, ActivityID: 1, SeverityID: severity, StatusID: status,
		Time:    now.UnixMilli(),
		Message: message,
		FindingInfo: map[string]any{
			"uid": uid, "title": title, "types": []string{strings.SplitN(strings.TrimPrefix(uid, findingSource+"."), ".", 2)[0]},
		},
		Resources: resources,
		Unmapped:  unmapped,
		Metadata: map[string]any{
			"version": ocsfVersion,
			"product": map[string]string{"name": "OmniNull", "vendor_name": "OmniNull", "version": s.agentVersion},
		},
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func humanAge(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d d", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	default:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	}
}

// anomalyFinding is the alert summary: the newest paging alerts, each
// described (nightshift_alerts.go), at the severity of the worst of them.
func (s *Server) anomalyFinding(now time.Time) (feedFinding, error) {
	win, err := s.store.SummariseOpenAnomalies(now.Add(-feedAnomalyWindow))
	if err != nil {
		return feedFinding{}, err
	}
	const uid, title = "ominull.anomalies.summary", "Open alerts"
	unmapped := map[string]any{"window_hours": int(feedAnomalyWindow.Hours()), "by_severity": win.BySeverity,
		"by_type": win.ByType, "by_host": win.ByHost, "tier": storage.TierPage, "severity_basis": "alert"}
	if win.Total == 0 {
		unmapped["alerts"] = []feedAlert{}
		return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
			"No new alerts in the last 24 h", nil, unmapped), nil
	}
	// Every alert of the window is judged (up to feedAlertScan), so an alert
	// that needs the owner is never hidden behind five that are explained.
	list, err := s.store.NewOpenAlerts(now.Add(-feedAnomalyWindow), feedAlertScan)
	if err != nil {
		return feedFinding{}, err
	}
	tuning := s.store.GetDetectionTuning()
	var needs, explained []feedAlert
	sev := ocsfSevInformational
	for _, a := range list {
		d := describeAlert(a, tuning)
		if d.Expected != "" {
			// The hub names it as the owner's own automation: listed for the
			// record, never a reason to page.
			explained = append(explained, d)
			continue
		}
		needs = append(needs, d)
		sev = max(sev, alertSeverity(a.Severity))
	}
	beyond := 0
	if len(list) == feedAlertScan && win.Total > feedAlertScan {
		// Beyond the scan: judge the rest by the window's own counts.
		for name, n := range win.BySeverity {
			if n > 0 {
				sev = max(sev, alertSeverity(name))
			}
		}
		beyond = win.Total - len(list)
	}
	// The alerts that page come first, so the list never hides one behind
	// report-only alerts; within a severity the newest stay first. Among the
	// pages, each incident's newest alert leads and its repeats follow, so a
	// lower-severity incident is never hidden behind another's repeats.
	slices.SortStableFunc(needs, func(a, b feedAlert) int { return alertSeverity(b.Severity) - alertSeverity(a.Severity) })
	needs = incidentsFirst(needs)
	alerts := append(needs, explained...)
	if len(alerts) > feedAlertMax {
		alerts = alerts[:feedAlertMax]
	}
	alerts = fitAlerts(alerts)
	more := max(0, win.Total-len(alerts))
	// more_paging counts the unlisted alerts that page (feedAlert.pages: a
	// classed page, or high or critical from before the classes; never one the
	// hub explains), so a reader that explains every listed one knows whether
	// anything it cannot see still asks. Alerts beyond the scan are unknown and
	// counted as paging.
	morePaging := beyond
	for _, d := range needs[min(len(alerts), len(needs)):] {
		if d.pages() {
			morePaging++
		}
	}
	unmapped["alerts"], unmapped["more"], unmapped["more_paging"] = alerts, more, morePaging
	msg := plural(win.Total, "new alert", "new alerts") + " in the last 24 h"
	if len(alerts) > 0 {
		msg = alerts[0].What
		if more+len(alerts) > 1 {
			msg += fmt.Sprintf(" (+%d more)", more+len(alerts)-1)
		}
	}
	return s.feedFinding(now, uid, title, sev, ocsfStatusNew, msg, nil, unmapped), nil
}

// huntFinding reports the hunt leads: the behavioural detectors' findings,
// which are kept for hunting and triage and never raised as alerts
// (storage/anomaly_tier.go). It is always informational, whatever the leads
// say, so it can sit on the board without ever asking for anyone.
func (s *Server) huntFinding(now time.Time) (feedFinding, error) {
	win, err := s.store.SummariseHuntLeads(now.Add(-feedAnomalyWindow))
	if err != nil {
		return feedFinding{}, err
	}
	unmapped := map[string]any{"window_hours": int(feedAnomalyWindow.Hours()), "tier": storage.TierHunt,
		"by_type": win.ByType, "by_host": win.ByHost, "by_class": win.ByClass, "muted_agent_heavy": win.Muted}
	const uid, title = "ominull.anomalies.hunt", "Hunt leads"
	if win.Total == 0 {
		return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
			"No hunt leads in the last 24 h", nil, unmapped), nil
	}
	msg := plural(win.Total, "finding", "findings") + " recorded in the last 24 h, kept for the record and not alerts"
	if win.Muted > 0 {
		msg += fmt.Sprintf(" (%d lowered to low on agent hosts)", win.Muted)
	}
	return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusNew, msg, nil, unmapped), nil
}

// feedDigestScan bounds the recorded findings the digest reads; feedDigestLines
// is how many groups it names.
const (
	feedDigestScan  = 2000
	feedDigestLines = 3
)

// digestFinding is the day's digest of the record and digest findings: one
// line per group (rule, host and program), the largest groups first, each
// named the way the alert list names an alert. It never asks: these findings
// are kept with their evidence for the record, and only pages ask. It took
// over the agent egress digest; ominull.anomalies.agent_egress stays in the
// feed as the same digest of the agent runtimes' findings, so the contract
// only grows.
func (s *Server) digestFinding(now time.Time) (feedFinding, error) {
	return s.recordedDigest(now, "ominull.anomalies.digest", "Recorded today", nil)
}

// agentEgressTypes are the findings of the per-runtime agent egress detector.
var agentEgressTypes = []string{"AGENT_NEW_DESTINATION", "AGENT_UPLOAD_VOLUME", "AGENT_DNS_BYPASS"}

// agentEgressFinding is the digest of the agent runtimes' recorded findings
// (a page among them is in the alert list).
func (s *Server) agentEgressFinding(now time.Time) (feedFinding, error) {
	return s.recordedDigest(now, "ominull.anomalies.agent_egress", "Agent runtimes recorded today", agentEgressTypes)
}

// recordedDigest digests the recorded findings of the last day, only those
// of the given types when types is not nil.
func (s *Server) recordedDigest(now time.Time, uid, title string, types []string) (feedFinding, error) {
	all, err := s.store.RecordedAlerts(now.Add(-feedAnomalyWindow), feedDigestScan)
	if err != nil {
		return feedFinding{}, err
	}
	list := all
	if types != nil {
		list = nil
		for _, a := range all {
			if slices.Contains(types, a.AnomalyType) {
				list = append(list, a)
			}
		}
	}
	type group struct {
		line  feedAlert
		count int
	}
	tuning := s.store.GetDetectionTuning()
	groups := map[string]*group{}
	var order []string
	byClass := map[string]int{}
	byType := map[string]int{}
	for _, a := range list {
		d := describeAlert(a, tuning)
		byClass[d.Class]++
		byType[a.AnomalyType]++
		key := a.AnomalyType + "|" + d.Host + "|" + d.Process
		g := groups[key]
		if g == nil {
			// The newest finding of the group names it.
			g = &group{line: d}
			groups[key] = g
			order = append(order, key)
		}
		g.count++
	}
	slices.SortStableFunc(order, func(a, b string) int { return groups[b].count - groups[a].count })
	var lines []map[string]any
	var named []string
	for _, key := range order[:min(len(order), feedDigestLines)] {
		g := groups[key]
		text := g.line.What
		if g.count > 1 {
			text += fmt.Sprintf(" (%d times)", g.count)
		}
		if g.line.Expected != "" {
			text += " (" + g.line.Expected + ")"
		}
		named = append(named, text)
		lines = append(lines, map[string]any{"type": g.line.Type, "host": g.line.Host, "class": g.line.Class, "count": g.count, "what": text})
	}
	unmapped := map[string]any{"window_hours": int(feedAnomalyWindow.Hours()), "by_class": byClass, "by_type": byType,
		"groups": len(order), "lines": lines, "truncated": len(all) == feedDigestScan}
	if len(list) == 0 {
		return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
			"Nothing recorded in the last 24 h", nil, unmapped), nil
	}
	msg := fmt.Sprintf("%s recorded in the last 24 h, none asking for you. Most common: %s",
		plural(len(list), "finding", "findings"), strings.Join(named, "; "))
	if rest := len(order) - len(named); rest > 0 {
		msg += fmt.Sprintf("; %s", plural(rest, "more group", "more groups"))
	}
	return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusNew, msg, nil, unmapped), nil
}

// detectionHealthFinding compares the incidents that paged in the last week
// with the page budget (page_budget_per_week). Over budget it is a note naming
// the noisiest rule, so the rule gets tuned; it never holds a page back.
func (s *Server) detectionHealthFinding(now time.Time) (feedFinding, error) {
	incidents, err := s.store.PagedIncidents(now.Add(-7*24*time.Hour), detector.DrillEndpointID)
	if err != nil {
		return feedFinding{}, err
	}
	budget := s.store.GetDetectionTuning().PageBudgetPerWeek
	byType := map[string]int{}
	for _, inc := range incidents {
		byType[inc.Type]++
	}
	noisiest, most := "", 0
	for typ, n := range byType {
		if n > most || (n == most && typ < noisiest) {
			noisiest, most = typ, n
		}
	}
	unmapped := map[string]any{"window_days": 7, "incidents": len(incidents), "budget": budget, "by_type": byType}
	const uid, title = "ominull.detection.health", "Detection health"
	if len(incidents) <= budget {
		return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
			fmt.Sprintf("%s paged in the last 7 days, within the weekly page budget of %d", plural(len(incidents), "incident", "incidents"), budget), nil, unmapped), nil
	}
	unmapped["noisiest"] = noisiest
	msg := fmt.Sprintf("%s paged in the last 7 days, more than the weekly page budget of %d. The noisiest rule is %s (%s); if those were not worth a page, tune that rule. Every page was still sent.",
		plural(len(incidents), "incident", "incidents"), budget, ruleName(noisiest), plural(most, "incident", "incidents"))
	if most == 1 {
		// No rule stands out: name them all.
		unmapped["noisiest"] = ""
		names := make([]string, 0, len(byType))
		for typ := range byType {
			names = append(names, ruleName(typ))
		}
		sort.Strings(names)
		msg = fmt.Sprintf("%s paged in the last 7 days, more than the weekly page budget of %d, each from a different rule (%s). No rule is repeating, so there is nothing to tune. Every page was still sent.",
			plural(len(incidents), "incident", "incidents"), budget, strings.Join(names, ", "))
	}
	return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusNew, msg, nil, unmapped), nil
}

// ruleName is a detector's type in owner words.
func ruleName(typ string) string {
	if name, ok := ruleNames[typ]; ok {
		return name
	}
	return strings.ToLower(strings.ReplaceAll(typ, "_", " "))
}

var ruleNames = map[string]string{
	"THREAT_INTEL_MATCH":    "threat list match",
	"DECOY_TOUCH":           "decoy touch",
	"NEW_PLACE_UPLOAD":      "upload to a new place",
	"AGENT_UPLOAD_VOLUME":   "agent upload volume",
	"C2_BEACONING":          "beacon",
	"LAB_ESCAPE":            "lab escape",
	"SENSITIVE_PORT_EGRESS": "sensitive port out",
	"LATERAL_PORT_SWEEP":    "local network sweep",
	"PORT_SCAN_RECON":       "port scan",
	"ENDPOINT_SILENT":       "agent went quiet",
}

func (s *Server) agentFinding(now time.Time) (feedFinding, error) {
	list, err := s.store.ListEndpoints("")
	if err != nil {
		return feedFinding{}, err
	}
	var servers, laptops []feedResource
	var longest time.Duration
	quiet := map[string]string{}
	presence := map[string]string{}
	active := 0
	for _, ep := range list {
		if ep.Status == "retired" {
			continue
		}
		active++
		if ep.Presence != "" && ep.Presence != storage.PresenceAlwaysOn {
			presence[ep.ID] = ep.Presence
		}
		age := now.Sub(ep.LastSeenAt)
		res := feedResource{Type: "endpoint", Name: ep.Hostname, UID: ep.ID}
		server := ep.RoleTag == "server"
		base := feedWorkstationQuiet
		if server {
			base = feedServerQuiet
		}
		allowance, watched := ep.QuietAllowance(base)
		switch {
		case !watched || age < allowance:
			continue
		case server:
			servers = append(servers, res)
			longest = max(longest, age)
		default:
			laptops = append(laptops, res)
		}
		quiet[ep.ID] = ep.LastSeenAt.UTC().Format(time.RFC3339)
	}
	unmapped := map[string]any{"active_agents": active, "last_seen": quiet, "presence": presence,
		"server_quiet_minutes": int(feedServerQuiet.Minutes()), "workstation_quiet_days": int(feedWorkstationQuiet.Hours() / 24),
		"intermittent_quiet_days": int(storage.IntermittentQuiet.Hours() / 24)}
	const uid, title = "ominull.agents.offline", "Quiet agents"
	resources := append(servers, laptops...)
	sort.Slice(resources, func(i, j int) bool { return resources[i].UID < resources[j].UID })
	switch {
	case len(servers) > 0:
		msg := fmt.Sprintf("%s offline (longest %s)", plural(len(servers), "server agent", "server agents"), humanAge(longest))
		if len(laptops) > 0 {
			msg += fmt.Sprintf("; %s", plural(len(laptops), "workstation agent quiet beyond its allowance", "workstation agents quiet beyond their allowance"))
		}
		return s.feedFinding(now, uid, title, ocsfSevMedium, ocsfStatusNew, msg, resources, unmapped), nil
	case len(laptops) > 0:
		return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusNew,
			fmt.Sprintf("%s; every server agent is reporting", plural(len(laptops), "workstation agent quiet beyond its allowance", "workstation agents quiet beyond their allowance")),
			resources, unmapped), nil
	}
	msg := fmt.Sprintf("All %s reporting", plural(active, "agent is", "agents are"))
	if parked := countPresence(presence, storage.PresenceParked); parked > 0 {
		msg = fmt.Sprintf("Every watched agent is reporting; %s", plural(parked, "parked endpoint is not watched", "parked endpoints are not watched"))
	}
	return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved, msg, nil, unmapped), nil
}

// feedInventoryMax bounds the inventory so it fits Nightshift's 4 KiB details
// cap (one "id|host|presence|role|isolated|status" line per endpoint, about
// 80 bytes as Nightshift measures it); feedOnlineWindow is how recently an agent must have reported to count
// as running now.
const (
	feedInventoryMax = 30
	feedOnlineWindow = 5 * time.Minute
)

// inventoryFinding reports every enrolled endpoint as the hub observes it:
// presence, role tag, isolation and whether it reported in the last few
// minutes. It is an observation for Nightshift's asset registry, which owns
// importance tiers and reconciles them against this; the hub never reads or
// sets a tier.
func (s *Server) inventoryFinding(now time.Time) (feedFinding, error) {
	list, err := s.store.ListEndpoints("")
	if err != nil {
		return feedFinding{}, err
	}
	rows := []string{}
	online, total := 0, 0
	for _, ep := range list {
		if ep.Status == "retired" {
			continue
		}
		total++
		status := "offline"
		if now.Sub(ep.LastSeenAt) < feedOnlineWindow {
			status = "online"
			online++
		}
		presence := ep.Presence
		if presence == "" {
			presence = storage.PresenceAlwaysOn
		}
		iso := "0"
		if ep.IsIsolated {
			iso = "1"
		}
		field := func(v string) string { return strings.ReplaceAll(v, "|", "/") }
		rows = append(rows, strings.Join([]string{field(ep.ID), field(ep.Hostname), field(presence), field(ep.RoleTag), iso, status}, "|"))
	}
	sort.Strings(rows)
	truncated := len(rows) > feedInventoryMax
	if truncated {
		rows = rows[:feedInventoryMax]
	}
	unmapped := map[string]any{"endpoints": rows, "fields": "id|host|presence|role|isolated|status", "total": total, "truncated": truncated}
	msg := fmt.Sprintf("%s enrolled, %d reporting now", plural(total, "endpoint", "endpoints"), online)
	return s.feedFinding(now, "ominull.inventory.endpoints", "Endpoint inventory", ocsfSevInformational, ocsfStatusResolved,
		msg, nil, unmapped), nil
}

func countPresence(presence map[string]string, want string) int {
	n := 0
	for _, p := range presence {
		if p == want {
			n++
		}
	}
	return n
}

func (s *Server) routerFindings(now time.Time) ([]feedFinding, error) {
	sources, err := s.store.ListRouterSources()
	if err != nil {
		return nil, err
	}
	const uid, title = "ominull.router.collector", "Router collector"
	if len(sources) == 0 {
		return []feedFinding{s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusNew,
			"No router collector has reported to the hub", nil, nil)}, nil
	}
	var silent, resources []feedResource
	var certIssues []string
	last := map[string]any{}
	var longest time.Duration
	for _, rs := range sources {
		res := feedResource{Type: "router", Name: rs.Label, UID: rs.ID}
		resources = append(resources, res)
		age := now.Sub(rs.LastSeenAt)
		last[rs.ID] = map[string]string{"last_seen_at": rs.LastSeenAt.UTC().Format(time.RFC3339), "last_result": rs.LastResult}
		if rs.LastSeenAt.IsZero() || age >= feedRouterQuiet {
			silent = append(silent, res)
			longest = max(longest, age)
		}
		if !rs.IdentityIssuedAt.IsZero() {
			left := rs.IdentityIssuedAt.Add(pki.ClientCertLifetime).Sub(now)
			if left < feedRouterCertWarnDays*24*time.Hour {
				certIssues = append(certIssues, rs.ID)
				last[rs.ID].(map[string]string)["certificate_expires_in_days"] = fmt.Sprint(int(left.Hours() / 24))
			}
		}
	}
	unmapped := map[string]any{"routers": last, "quiet_minutes": int(feedRouterQuiet.Minutes())}
	var out []feedFinding
	if len(silent) > 0 {
		out = append(out, s.feedFinding(now, uid, title, ocsfSevMedium, ocsfStatusNew,
			fmt.Sprintf("%s silent for %s", plural(len(silent), "router collector", "router collectors"), humanAge(longest)), silent, unmapped))
	} else {
		out = append(out, s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
			fmt.Sprintf("%s reporting", plural(len(sources), "router collector", "router collectors")), resources, unmapped))
	}
	const certUID, certTitle = "ominull.router.certificate", "Router client certificate"
	if len(certIssues) > 0 {
		out = append(out, s.feedFinding(now, certUID, certTitle, ocsfSevMedium, ocsfStatusNew,
			fmt.Sprintf("%s within %d days of expiry: reissue with POST /api/v1/router/identity",
				plural(len(certIssues), "router certificate is", "router certificates are"), feedRouterCertWarnDays), nil, map[string]any{"routers": certIssues}))
	} else {
		out = append(out, s.feedFinding(now, certUID, certTitle, ocsfSevInformational, ocsfStatusResolved,
			"Router client certificates are not near expiry", nil, nil))
	}
	return out, nil
}

// healthFindings builds every finding of the hub's state. A section that
// cannot be read says so rather than vanishing: an empty list would look like
// a quiet fleet.
func (s *Server) healthFindings(now time.Time) []feedFinding {
	findings := []feedFinding{s.feedFinding(now, "ominull.hub", "Hub", ocsfSevInformational, ocsfStatusResolved,
		"OmniNull hub "+s.agentVersion+" answering", nil, nil)}
	add := func(section string, f []feedFinding, err error) {
		if err != nil {
			findings = append(findings, s.feedFinding(now, "ominull.hub."+section+"_unavailable", "Hub section unavailable",
				ocsfSevMedium, ocsfStatusNew, "The hub could not read its "+section, nil, nil))
			return
		}
		findings = append(findings, f...)
	}
	a, err := s.anomalyFinding(now)
	add("anomalies", []feedFinding{a}, err)
	hl, err := s.huntFinding(now)
	add("hunt_leads", []feedFinding{hl}, err)
	dg, err := s.digestFinding(now)
	add("digest", []feedFinding{dg}, err)
	ae, err := s.agentEgressFinding(now)
	add("agent_egress", []feedFinding{ae}, err)
	dh, err := s.detectionHealthFinding(now)
	add("detection_health", []feedFinding{dh}, err)
	g, err := s.agentFinding(now)
	add("agents", []feedFinding{g}, err)
	acf, err := s.agentCertFinding(now)
	add("agent_certificates", []feedFinding{acf}, err)
	pef, err := s.policyExpiryFinding(now)
	add("policy_expiry", []feedFinding{pef}, err)
	inv, err := s.inventoryFinding(now)
	add("inventory", []feedFinding{inv}, err)
	rf, err := s.routerFindings(now)
	add("router", rf, err)
	sf, err := s.storageFinding(now)
	add("storage", sf, err)
	mf, err := s.maintenanceFindings(now)
	add("maintenance", mf, err)
	dcf, err := s.decisionFindings(now)
	add("maintenance_decisions", dcf, err)
	rnf, err := s.runFindings(now)
	add("maintenance_runs", rnf, err)
	cpf, err := s.complianceFindings(now)
	add("maintenance_compliance", cpf, err)
	// An unsound tuning row is reported even when the change log cannot be read.
	df, err := s.detectionPolicySection(now)
	findings = append(findings, df...)
	if err != nil {
		add("detection_policy", nil, err)
	}
	return findings
}

// handleHealthFindings: GET /api/v1/health/findings, the raw list for
// diagnostics (fleet administrator).
func (s *Server) handleHealthFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	now := time.Now().UTC()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"generated_at": now.Format(time.RFC3339), "findings": s.healthFindings(now)})
}

// incidentsFirst orders described alerts (already worst first): the newest
// alert of each paging incident, then every other alert that pages, then the
// rest, each group keeping its order.
func incidentsFirst(in []feedAlert) []feedAlert {
	var lead, pages, rest []feedAlert
	seen := map[string]bool{}
	for _, d := range in {
		switch {
		case !d.pages():
			rest = append(rest, d)
		case d.Incident != "" && !seen[d.Incident]:
			seen[d.Incident] = true
			lead = append(lead, d)
		default:
			pages = append(pages, d)
		}
	}
	return append(append(lead, pages...), rest...)
}
