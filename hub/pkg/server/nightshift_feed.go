package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"ominull/hub/pkg/pki"
	"ominull/hub/pkg/storage"
)

// Nightshift findings feed.
//
// Nightshift, the host steward, pulls one summarised findings document from
// the hub every cycle and shows it on its board. The document follows the
// contract Nightshift owns (nightshift.findings/v1: an OCSF Detection Finding
// subset, documented in Nightshift's docs/ingest.md). Neither side imports the
// other; this file and that document are the whole interface.
//
// The feed carries counts and states, not telemetry: how many anomalies are
// open, which agents have gone quiet, whether the router collector is still
// reporting. Messages hold only counts, because Nightshift may push them;
// device names stay in the structured fields, which only its board shows.
//
// Nightshift authenticates with its own key, issued by an administrator and
// stored here only as a SHA-256. That key opens this one read-only route and
// nothing else: it is not a tenant key and no other middleware knows it.
// Reissuing it revokes the previous one.

const (
	nightshiftFeedKeySetting = "nightshift_feed_key_sha256"
	nightshiftSchema         = "nightshift.findings/v1"
	nightshiftSource         = "ominull"
	ocsfVersion              = "1.3.0"

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
	ocsfStatusNew        = 1
	ocsfStatusResolved   = 4
)

func hashFeedKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// nightshiftFeedAuth admits the Nightshift feed key on this route only, and
// otherwise the normal credentials restricted to a fleet administrator: the
// feed is fleet-wide, so an administrator scoped to one tenant is refused.
func (s *Server) nightshiftFeedAuth(next http.HandlerFunc) http.HandlerFunc {
	fallback := s.authMiddleware(requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Tenant-ID") != "" {
			writeJSONError(w, http.StatusForbidden, "the Nightshift feed is fleet-wide; a tenant administrator cannot read it")
			return
		}
		next(w, r)
	}))
	return func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if want, _ := s.store.GetSetting(nightshiftFeedKeySetting); key != "" && want != "" && secretEqual(hashFeedKey(key), want) {
			if s.throttle.blocked(clientIP(r)) {
				w.Header().Set("Retry-After", "60")
				writeJSONError(w, http.StatusTooManyRequests, "too many failed authentication attempts; try again shortly")
				return
			}
			for _, h := range []string{"X-Role", "X-Tenant-ID", "X-Username", "X-User-ID", "X-Client-CN", "X-Device-Endpoint-ID", "X-Operator-ID", "X-Auth-Method", "X-Router-ID"} {
				r.Header.Del(h)
			}
			r.Header.Set("X-Role", "nightshift-feed")
			r.Header.Set("X-Username", "nightshift")
			r.Header.Set("X-Auth-Method", "feed-key")
			next(w, r)
			return
		}
		fallback(w, r)
	}
}

// handleNightshiftFeedKey issues the feed key. Admin only; the key is shown
// once and only its hash is kept.
func (s *Server) handleNightshiftFeedKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Header.Get("X-Role") != "admin" || r.Header.Get("X-Tenant-ID") != "" {
		writeJSONError(w, http.StatusForbidden, "only an administrator can issue the Nightshift feed key")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "generating the key failed")
		return
	}
	key := "nsf_" + hex.EncodeToString(raw)
	if err := s.store.SetSetting(nightshiftFeedKeySetting, hashFeedKey(key)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "the key could not be saved")
		return
	}
	s.audit(r, "NIGHTSHIFT_FEED_KEY_ISSUED", "nightshift", "Issued the Nightshift findings feed key; any earlier key is revoked")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{"key": key, "route": "/api/v1/integrations/nightshift/findings"})
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
			"uid": uid, "title": title, "types": []string{strings.SplitN(strings.TrimPrefix(uid, nightshiftSource+"."), ".", 2)[0]},
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

func (s *Server) anomalyFinding(now time.Time) (feedFinding, error) {
	win, err := s.store.SummariseOpenAnomalies(now.Add(-feedAnomalyWindow))
	if err != nil {
		return feedFinding{}, err
	}
	unmapped := map[string]any{"window_hours": int(feedAnomalyWindow.Hours()), "by_severity": win.BySeverity,
		"by_type": win.ByType, "by_host": win.ByHost, "backlog": win.Backlog, "tier": storage.TierPage}
	const uid, title = "ominull.anomalies.summary", "Open anomalies"
	if win.Total == 0 {
		return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
			fmt.Sprintf("No new open anomalies in the last 24 h (%d open in the backlog)", win.Backlog), nil, unmapped), nil
	}
	crit, high := win.BySeverity["CRITICAL"], win.BySeverity["HIGH"]
	// Only a critical verdict asks for attention; the rest is volume the
	// prove-out is measuring, so it is a note on the board.
	sev := ocsfSevInformational
	if crit > 0 {
		sev = ocsfSevHigh
	}
	msg := fmt.Sprintf("%s in the last 24 h (%d critical, %d high); %d open in the backlog",
		plural(win.Total, "new open anomaly", "new open anomalies"), crit, high, win.Backlog)
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
		"by_type": win.ByType, "by_host": win.ByHost, "muted_agent_heavy": win.Muted}
	const uid, title = "ominull.anomalies.hunt", "Hunt leads"
	if win.Total == 0 {
		return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
			"No hunt leads in the last 24 h", nil, unmapped), nil
	}
	msg := fmt.Sprintf("%s in the last 24 h (behavioural, not alerts; %d muted on agent-heavy hosts)",
		plural(win.Total, "hunt lead", "hunt leads"), win.Muted)
	return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusNew, msg, nil, unmapped), nil
}

// agentEgressTypes are the findings of the per-runtime agent egress detector.
var agentEgressTypes = []string{"AGENT_NEW_DESTINATION", "AGENT_UPLOAD_VOLUME", "AGENT_DNS_BYPASS"}

// agentEgressFinding reports what the agent runtimes did that their own
// baselines did not expect, at the severity of the worst of it: an ordinary
// new destination is a note, since runtimes gain endpoints with their
// updates; one on rented compute, an unusual hour of uploads, or a tool
// resolving names past the router asks for a look.
func (s *Server) agentEgressFinding(now time.Time) (feedFinding, error) {
	win, err := s.store.SummariseOpenAnomalies(now.Add(-feedAnomalyWindow))
	if err != nil {
		return feedFinding{}, err
	}
	counts := map[string]int{}
	total, high := 0, 0
	for _, t := range agentEgressTypes {
		counts[t] = win.ByType[t]
		total += win.ByType[t]
		high += win.HighByType[t]
	}
	unmapped := map[string]any{"window_hours": int(feedAnomalyWindow.Hours()), "by_type": counts}
	const uid, title = "ominull.anomalies.agent_egress", "Agent egress"
	if total == 0 {
		return s.feedFinding(now, uid, title, ocsfSevInformational, ocsfStatusResolved,
			"Agent runtimes stayed inside their baselines in the last 24 h", nil, unmapped), nil
	}
	sev := ocsfSevLow
	if high > 0 {
		sev = ocsfSevHigh
	}
	msg := fmt.Sprintf("Agent egress in the last 24 h: %d new destinations, %d unusual upload hours, %d resolver bypasses",
		counts["AGENT_NEW_DESTINATION"], counts["AGENT_UPLOAD_VOLUME"], counts["AGENT_DNS_BYPASS"])
	return s.feedFinding(now, uid, title, sev, ocsfStatusNew, msg, nil, unmapped), nil
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

// handleNightshiftFeed serves the findings document.
func (s *Server) handleNightshiftFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	now := time.Now().UTC()
	findings := []feedFinding{s.feedFinding(now, "ominull.hub", "Hub", ocsfSevInformational, ocsfStatusResolved,
		"OmniNull hub "+s.agentVersion+" answering", nil, nil)}
	// A section that cannot be read says so rather than vanishing: an empty
	// feed would look like a quiet fleet.
	add := func(section string, f []feedFinding, err error) {
		if err != nil {
			findings = append(findings, s.feedFinding(now, "ominull.hub."+section+"_unavailable", "Hub section unavailable",
				ocsfSevMedium, ocsfStatusNew, "The hub could not read its "+section+" for Nightshift", nil, nil))
			return
		}
		findings = append(findings, f...)
	}
	a, err := s.anomalyFinding(now)
	add("anomalies", []feedFinding{a}, err)
	hl, err := s.huntFinding(now)
	add("hunt_leads", []feedFinding{hl}, err)
	ae, err := s.agentEgressFinding(now)
	add("agent_egress", []feedFinding{ae}, err)
	g, err := s.agentFinding(now)
	add("agents", []feedFinding{g}, err)
	inv, err := s.inventoryFinding(now)
	add("inventory", []feedFinding{inv}, err)
	rf, err := s.routerFindings(now)
	add("router", rf, err)
	doc := map[string]any{
		"schema":       nightshiftSchema,
		"source":       nightshiftSource,
		"generated_at": now.Format(time.RFC3339),
		"findings":     findings,
	}
	// v2 is asked for, never assumed: a v1 validator rejects any other schema
	// string, so v1 stays the default until every reader has moved.
	switch c := r.URL.Query().Get("contract"); c {
	case "", "v1":
	case "v2", "v3", "v4":
		v1, _ := json.Marshal(doc)
		records, truncated, err := s.anomalyRecords(now, min(feedRecordBytes, feedDocumentBytes-len(v1)), c == "v4")
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "the hub could not read its anomaly records for Nightshift")
			return
		}
		doc["schema"] = nightshiftSchemaV2
		doc["anomaly_records"] = records
		doc["anomaly_records_truncated"] = truncated
		if c == "v3" || c == "v4" {
			v2, _ := json.Marshal(doc)
			blocks, cut, err := s.dataInventoryBlocks(now, feedDocumentBytesV3-len(v2)-256)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "the hub could not read its data inventory for Nightshift")
				return
			}
			doc["schema"] = nightshiftSchemaV3
			doc["data_inventory"] = blocks
			doc["data_inventory_truncated"] = cut
		}
		if c == "v4" {
			doc["schema"] = nightshiftSchemaV4
		}
	default:
		writeJSONError(w, http.StatusBadRequest, "unknown contract; this hub serves v1, v2, v3 and v4")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, doc)
}
